package teams

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus-community/prom-label-proxy/injectproxy"
)

type Team struct {
	ID          int64  `json:"id"`
	OrgID       int64  `json:"orgId"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	AvatarURL   string `json:"avatarURL"`
	MemberCount int64  `json:"memberCount"`
}

// GrafanaTeamsEnforcer enforces label values based on the Grafana teams a user is a member of.
type GrafanaTeamsEnforcer struct {
	KeyFunc     keyfunc.Keyfunc
	Client      http.Client
	GrafanaUrl  url.URL
	GrafanaUser string
	GrafanaPass string
}

func (gte GrafanaTeamsEnforcer) ExtractLabel(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signedToken := r.Header.Get("X-Grafana-Id")
		if signedToken == "" {
			slog.Error("no X-Grafana-Id header present")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(signedToken, gte.KeyFunc.Keyfunc)
		if err != nil {
			slog.Error("error while parsing token", "error", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// extract user id from subject
		sub, err := token.Claims.GetSubject()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		userId := strings.Split(sub, ":")[1]

		aud, err := token.Claims.GetAudience()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// rfc7519 means that aud is generally an array, but in this case its just a string
		if len(aud) != 1 {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		orgId, err := strconv.ParseInt(strings.Split(aud[0], ":")[1], 0, 64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		teams, err := gte.fetchTeamsForUser(userId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// filter only for teams in the same org
		var teamNames []string
		for _, t := range teams {
			if t.OrgID == orgId {
				teamNames = append(teamNames, t.Name)
			}
		}

		next(w, r.WithContext(injectproxy.WithLabelValues(r.Context(), teamNames)))
	})
}

func (gte GrafanaTeamsEnforcer) fetchTeamsForUser(userId string) ([]Team, error) {
	path := fmt.Sprintf("/api/users/%s/teams", userId)
	u := gte.GrafanaUrl.JoinPath(path)
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request failed: %w", err)
	}
	req.SetBasicAuth(gte.GrafanaUser, gte.GrafanaPass)
	r, err := gte.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexepected status: %d", r.StatusCode)
	}

	var teams []Team
	if err = json.NewDecoder(r.Body).Decode(&teams); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}
	return teams, nil
}
