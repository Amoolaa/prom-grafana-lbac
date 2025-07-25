# prom-grafana-lbac

prom-grafana-lbac enforces a given label in a given PromQL query, in Prometheus API responses or in Alertmanager API requests coming from a Grafana instance based on the [Grafana teams](https://grafana.com/docs/grafana/latest/administration/team-management/) the requestor is a member of. This enables read multi-tenancy for observability platforms using Prometheus (or Prometheus-compatible backends, such as Thanos and Mimir) as a Grafana datasource purely through Grafana teams.

This project is heavily inspired by [prom-label-proxy](https://github.com/prometheus-community/prom-label-proxy) and uses the same CLI argments. 

## Design

Grafana sends an X-Grafana-Id header when it proxies datasources. This header is a signed JWT with the user and org that the request was made from. We can validate and verify the token using Grafana's public JWKS exposed on `/api/signing-keys/keys`.

Once the user is verified, we call Grafana to fetch the list of teams that the user is a member of. The [User API](https://grafana.com/docs/grafana/latest/developers/http_api/user/) requires authenticating using basic auth with a Grafana admin's credentials.

The names of teams that a user is part of is then used as the label values enforced in the query.