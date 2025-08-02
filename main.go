package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/Amoolaa/prom-grafana-lbac/pkg/teams"
	"github.com/urfave/cli/v2"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/metalmatze/signal/internalserver"
	"github.com/oklog/run"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
)

var (
	grafanaJWKSPath = "/api/signing-keys/keys"
)

var (
	insecureListenAddress  string
	internalListenAddress  string
	upstream               string
	label                  string
	enableLabelAPIs        bool
	unsafePassthroughPaths string // Comma-delimited string.
	errorOnReplace         bool
	headerUsesListSyntax   bool
	rulesWithActiveAlerts  bool
	grafanaUrl             string
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:        "insecure-listen-address",
		Usage:       "The address the prom-label-proxy HTTP server should listen on.",
		Destination: &insecureListenAddress,
	},
	&cli.StringFlag{
		Name:        "internal-listen-address",
		Usage:       "The address the internal prom-label-proxy HTTP server should listen on to expose metrics about itself.",
		Destination: &internalListenAddress,
	},
	&cli.StringFlag{
		Name:        "upstream",
		Usage:       "The upstream URL to proxy to.",
		Destination: &upstream,
	},
	&cli.StringFlag{
		Name:        "label",
		Usage:       "The label name to enforce in all proxied PromQL queries.",
		Destination: &label,
	},
	&cli.BoolFlag{
		Name: "enable-label-apis",
		Usage: "When specified proxy allows to inject label to label APIs like /api/v1/labels and /api/v1/label/<name>/values. " +
			"NOTE: Enable with care because filtering by matcher is not implemented in older versions of Prometheus (>= v2.24.0 required) and Thanos (>= v0.18.0 required, >= v0.23.0 recommended). If enabled and " +
			"any labels endpoint does not support selectors, the injected matcher will have no effect.",
		Value:       false,
		Destination: &enableLabelAPIs,
	},
	&cli.StringFlag{
		Name: "unsafe-passthrough-paths",
		Usage: "Comma delimited allow list of exact HTTP path segments that should be allowed to hit upstream URL without any enforcement. " +
			"This option is checked after Prometheus APIs, you cannot override enforced API endpoints to be not enforced with this option. Use carefully as it can easily cause a data leak if the provided path is an important " +
			"API (like /api/v1/configuration) which isn't enforced by prom-label-proxy. NOTE: \"all\" matching paths like \"/\" or \"\" and regex are not allowed.",
		Destination: &unsafePassthroughPaths,
	},
	&cli.BoolFlag{
		Name:        "error-on-replace",
		Usage:       "When specified, the proxy will return HTTP status code 400 if the query already contains a label matcher that differs from the one the proxy would inject.",
		Value:       false,
		Destination: &errorOnReplace,
	},
	&cli.BoolFlag{
		Name:        "header-uses-list-syntax",
		Usage:       "When specified, the header line value will be parsed as a comma-separated list. This allows a single tenant header line to specify multiple tenant names.",
		Value:       false,
		Destination: &headerUsesListSyntax,
	},
	&cli.BoolFlag{
		Name:        "rules-with-active-alert",
		Usage:       "When true, the proxy will return alerting rules with active alerts matching the tenant label even when the tenant label isn't present in the rule's labels.",
		Value:       false,
		Destination: &rulesWithActiveAlerts,
	},
	&cli.StringFlag{
		Name:        "grafana-url",
		Usage:       "Grafana URL used to fetch teams, JWKS.",
		Destination: &grafanaUrl,
	},
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	app := &cli.App{
		Name:  "prom-grafana-lbac",
		Usage: "A label-based access control proxy to enable multi-tenant read access in Prometheus by enforcing label restrictions based on Grafana teams membership.",
		Flags: flags,
		Action: func(*cli.Context) error {
			if os.Getenv("GRAFANA_ADMIN_USER") == "" {
				log.Fatalf("GRAFANA_ADMIN_USER not present")
			}

			if os.Getenv("GRAFANA_ADMIN_PASS") == "" {
				log.Fatalf("GRAFANA_ADMIN_PASS not present")
			}

			upstreamURL, err := url.Parse(upstream)
			if err != nil {
				log.Fatalf("Failed to build parse upstream URL: %v", err)
			}

			if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
				log.Fatalf("Invalid scheme for upstream URL %q, only 'http' and 'https' are supported", upstream)
			}

			url, err := url.Parse(grafanaUrl)
			if err != nil {
				log.Fatalf("Failed to build parse grafana URL: %v", err)
			}

			if url.Scheme != "http" && url.Scheme != "https" {
				log.Fatalf("Invalid scheme for grafana URL %q, only 'http' and 'https' are supported", upstream)
			}

			reg := prometheus.NewRegistry()
			reg.MustRegister(
				collectors.NewGoCollector(),
				collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			)

			opts := []injectproxy.Option{injectproxy.WithPrometheusRegistry(reg)}
			if enableLabelAPIs {
				opts = append(opts, injectproxy.WithEnabledLabelsAPI())
			}

			if len(unsafePassthroughPaths) > 0 {
				opts = append(opts, injectproxy.WithPassthroughPaths(strings.Split(unsafePassthroughPaths, ",")))
			}

			if errorOnReplace {
				opts = append(opts, injectproxy.WithErrorOnReplace())
			}

			if rulesWithActiveAlerts {
				opts = append(opts, injectproxy.WithActiveAlerts())
			}

			k, err := keyfunc.NewDefaultCtx(context.Background(), []string{url.JoinPath(grafanaJWKSPath).String()})
			if err != nil {
				log.Fatalf("failed to create a keyfunc.Keyfunc from url: %v", err)
			}

			c := cache.New(5*time.Minute, 10*time.Minute)

			extractLabeler := teams.GrafanaTeamsEnforcer{
				KeyFunc: k,
				Cache:   *c,
				Client: http.Client{
					Timeout: 5 * time.Second,
				},
				GrafanaUrl:  *url,
				GrafanaUser: os.Getenv("GRAFANA_ADMIN_USER"),
				GrafanaPass: os.Getenv("GRAFANA_ADMIN_PASS"),
			}

			var g run.Group

			{
				// Run the insecure HTTP server.
				routes, err := injectproxy.NewRoutes(upstreamURL, label, extractLabeler, opts...)
				if err != nil {
					log.Fatalf("Failed to create injectproxy Routes: %v", err)
				}

				mux := http.NewServeMux()
				mux.Handle("/", routes)

				l, err := net.Listen("tcp", insecureListenAddress)
				if err != nil {
					log.Fatalf("Failed to listen on insecure address: %v", err)
				}

				srv := &http.Server{Handler: mux}

				g.Add(func() error {
					log.Printf("Listening insecurely on %v", l.Addr())
					if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
						log.Printf("Server stopped with %v", err)
						return err
					}
					return nil
				}, func(error) {
					srv.Close()
				})
			}

			if internalListenAddress != "" {
				// Run the internal HTTP server.
				h := internalserver.NewHandler(
					internalserver.WithName("Internal prom-label-proxy API"),
					internalserver.WithPrometheusRegistry(reg),
					internalserver.WithPProf(),
				)
				// Run the HTTP server.
				l, err := net.Listen("tcp", internalListenAddress)
				if err != nil {
					log.Fatalf("Failed to listen on internal address: %v", err)
				}

				srv := &http.Server{Handler: h}

				g.Add(func() error {
					log.Printf("Listening on %v for metrics and pprof", l.Addr())
					if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
						log.Printf("Internal server stopped with %v", err)
						return err
					}
					return nil
				}, func(error) {
					srv.Close()
				})
			}

			g.Add(run.SignalHandler(context.Background(), syscall.SIGINT, syscall.SIGTERM))

			if err := g.Run(); err != nil {
				if !errors.As(err, &run.SignalError{}) {
					log.Printf("Server stopped with %v", err)
					os.Exit(1)
				}
				log.Print("Caught signal; exiting gracefully...")
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
