package http

import (
	"github.com/portainer/portainer"

	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/gorilla/mux"
)

// DockerHandler represents an HTTP API handler for proxying requests to the Docker API.
type DockerHandler struct {
	*mux.Router
	Logger            *log.Logger
	middleWareService *middleWareService
	proxy             http.Handler
}

// NewDockerHandler returns a new instance of DockerHandler.
func NewDockerHandler(middleWareService *middleWareService) *DockerHandler {
	h := &DockerHandler{
		Router:            mux.NewRouter(),
		Logger:            log.New(os.Stderr, "", log.LstdFlags),
		middleWareService: middleWareService,
	}
	h.PathPrefix("/").Handler(middleWareService.addMiddleWares(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.proxyRequestsToDockerAPI(w, r)
	})))
	return h
}

func (handler *DockerHandler) proxyRequestsToDockerAPI(w http.ResponseWriter, r *http.Request) {
	if handler.proxy != nil {
		handler.proxy.ServeHTTP(w, r)
	} else {
		Error(w, portainer.ErrNoActiveEndpoint, http.StatusNotFound, handler.Logger)
	}
}

func (handler *DockerHandler) setupProxy(endpoint *portainer.Endpoint) error {
	var proxy http.Handler
	endpointURL, err := url.Parse(endpoint.URL)
	if err != nil {
		return err
	}
	if endpointURL.Scheme == "tcp" {
		if endpoint.TLS {
			proxy, err = newHTTPSProxy(endpointURL, endpoint)
			if err != nil {
				return err
			}
		} else {
			proxy = newHTTPProxy(endpointURL)
		}
	} else {
		// Assume unix:// scheme
		proxy = newSocketProxy(endpointURL.Path)
	}
	handler.proxy = proxy
	return nil
}

// singleJoiningSlash from golang.org/src/net/http/httputil/reverseproxy.go
// included here for use in NewSingleHostReverseProxyWithHostHeader
// because its used in NewSingleHostReverseProxy from golang.org/src/net/http/httputil/reverseproxy.go
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// NewSingleHostReverseProxyWithHostHeader is based on NewSingleHostReverseProxy
// from golang.org/src/net/http/httputil/reverseproxy.go and merely sets the Host
// HTTP header, which NewSingleHostReverseProxy deliberately preserves
func NewSingleHostReverseProxyWithHostHeader(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		req.Host = req.URL.Host
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}
	return &httputil.ReverseProxy{Director: director}
}

func newHTTPProxy(u *url.URL) http.Handler {
	u.Scheme = "http"
	return NewSingleHostReverseProxyWithHostHeader(u)
}

func newHTTPSProxy(u *url.URL, endpoint *portainer.Endpoint) (http.Handler, error) {
	u.Scheme = "https"
	proxy := NewSingleHostReverseProxyWithHostHeader(u)
	config, err := createTLSConfiguration(endpoint.TLSCACertPath, endpoint.TLSCertPath, endpoint.TLSKeyPath)
	if err != nil {
		return nil, err
	}
	proxy.Transport = &http.Transport{
		TLSClientConfig: config,
	}
	return proxy, nil
}

func newSocketProxy(path string) http.Handler {
	return &unixSocketHandler{path}
}

// unixSocketHandler represents a handler to proxy HTTP requests via a unix:// socket
type unixSocketHandler struct {
	path string
}

func clearEnv(m *map[string]interface{}) {
	for k, v := range *m {
		if k == "Env" {
			delete(*m, k)
		} else {
			switch vv := v.(type) {
				case map[string]interface{}:
					clearEnv(&vv)
			}
		}
	}
}

func stringSlicePos(slice []interface{}, predicate func(value string) bool) int {
	for i, v := range slice {
		if (predicate(v.(string))) {
			return i
		}
	}
	return -1
}

func clearProcessCommandArgs(m *map[string]interface{}) {
	titles := (*m)["Titles"].([]interface{})
	cmdIdx := stringSlicePos(titles, func(value string) bool { return value == "CMD" || value == "COMMAND" })
	if cmdIdx != -1 {
		processes := (*m)["Processes"].([]interface{})
		for _, process := range processes {
			processTyped := process.([]interface{})
			processTyped[cmdIdx] = strings.SplitN(processTyped[cmdIdx].(string), " ", 2)[0]
		}
	}
}

func (h *unixSocketHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := net.Dial("unix", h.path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c := httputil.NewClientConn(conn, nil)
	defer c.Close()

	res, err := c.Do(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()

	for k, vv := range res.Header {
		if k != "Content-Length" {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
	}

	if !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		if _, err := io.Copy(w, res.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	var jsonData interface{}

	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&jsonData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return	
	}

	switch jsonDataTyped := jsonData.(type) {
		case map[string]interface{}:
			clearEnv(&jsonDataTyped)

			matched, err := regexp.MatchString("/containers/[0-9a-fA-F]+/top$", r.URL.Path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return	
			}
			if matched {
				clearProcessCommandArgs(&jsonDataTyped)
			}
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(&jsonData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}