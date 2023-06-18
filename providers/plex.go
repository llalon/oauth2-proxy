package providers

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// PlexProvider represents an PLEX based Identity Provider
type PlexProvider struct {
	*ProviderData
}

// NewPlexProvider initiates a new PlexProvider
func NewPlexProvider(p *ProviderData, opts options.PlexOptions) *PlexProvider {
	return nil
}

//
//func (p *PlexProvider) Data() *ProviderData {
//	// Implement the Data() method to return the provider-specific data
//}
//
//func (p *PlexProvider) GetLoginURL(redirectURI, finalRedirect, nonce string, extraParams url.Values) string {
//	// Implement the GetLoginURL() method to generate the login URL for your provider
//}
//
//func (p *PlexProvider) Redeem(ctx context.Context, redirectURI, code, codeVerifier string) (*sessions.SessionState, error) {
//	// Implement the Redeem() method to exchange the code for an access token and session state
//}
//
//func (p *PlexProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
//	// ToDo
//}
//
//func (p *PlexProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
//	// Implement the EnrichSession() method to enrich or modify the session state
//}
//
//func (p *PlexProvider) Authorize(ctx context.Context, s *sessions.SessionState) (bool, error) {
//	// Implement the Authorize() method to perform authorization checks for the session
//}
//
//func (p *PlexProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
//	// Implement the ValidateSession() method to validate the session state
//}
//
//func (p *PlexProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
//	// Implement the RefreshSession() method to refresh the session
//}
//
//func (p *PlexProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
//	// Implement the CreateSessionFromToken() method to create a session state from a token
//}

type ServersResponse struct {
	Servers []ServersResponseServer `xml:"Server"`
}

type ServersResponseServer struct {
	AccessToken       string `xml:"accessToken,attr"`
	Name              string `xml:"name,attr"`
	Address           string `xml:"address,attr"`
	Port              int    `xml:"port,attr"`
	Version           string `xml:"version,attr"`
	Scheme            string `xml:"scheme,attr"`
	Host              string `xml:"host,attr"`
	LocalAddresses    string `xml:"localAddresses,attr"`
	MachineIdentifier string `xml:"machineIdentifier,attr"`
	CreatedAt         int64  `xml:"createdAt,attr"`
	UpdatedAt         int64  `xml:"updatedAt,attr"`
	Owned             int    `xml:"owned,attr"`
	Synced            int    `xml:"synced,attr"`
}

type PinResponse struct {
	ID   int    `json:"id"`
	Code string `json:"code"`
}

type TokenResponse struct {
	Token string `json:"authToken"`
}

type UserResponse struct {
	ID       int    `json:"id"`
	UUID     string `json:"uuid"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

func getServerList(token string) (*ServersResponse, error) {
	url := "https://plex.tv/pms/servers"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	headers := getPlexHeaders()

	req.Header.Set("X-Plex-Token", token)
	req.Header.Set("X-Plex-Client-Identifier", headers["X-Plex-Client-Identifier"])
	req.Header.Set("X-Plex-Product", headers["X-Plex-Product"])
	req.Header.Set("X-Plex-Version", headers["X-Plex-Version"])

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	var container struct {
		Servers []ServersResponseServer `xml:"Server"`
	}

	err = xml.Unmarshal(body, &container)
	if err != nil {
		return nil, err
	}

	serversResponse := &ServersResponse{
		Servers: container.Servers,
	}

	return serversResponse, nil
}

func cliTokenFlow() *TokenResponse {
	// Get pin
	pin, _ := getPlexOAuthPin()

	// Get URL from pin code
	url := getUrl(pin.Code)

	fmt.Println("")
	fmt.Println("Follow the link to authenticate with Plex:")
	fmt.Println("")
	fmt.Println(url)
	fmt.Println("")
	fmt.Println("Press enter after login")

	// Check if user logins - gets token
	token := pollForToken(pin.ID)

	return token
}

func pollForToken(pin int) *TokenResponse {
	for {
		// wait for enter
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')

		token, err := getTokenIfAuthenticated(pin)

		if err == nil && "" != token.Token {
			return token
		} else {
			fmt.Println("Failed to retrieve token. Press enter to try again")
		}
	}
}

func getUser(token string) (*UserResponse, error) {
	url := "https://plex.tv/users/account.json"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Plex-Token", token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var data struct {
		User UserResponse `json:"user"`
	}

	err = json.NewDecoder(response.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data.User, nil
}

func getPlexHeaders() map[string]string {
	return map[string]string{
		"Accept":                          "application/json",
		"X-Plex-Product":                  "My Title",
		"X-Plex-Version":                  "2.0",
		"X-Plex-Client-Identifier":        "0cf0bbc6-7ac0-4d44-a416-2b4106e7d2f8",
		"X-Plex-Model":                    "Plex OAuth",
		"X-Plex-Platform":                 "osName",
		"X-Plex-Platform-Version":         "osVersion",
		"X-Plex-Device":                   "browserName",
		"X-Plex-Device-Name":              "browserVersion",
		"X-Plex-Device-Screen-Resolution": "800x600",
		"X-Plex-Language":                 "en",
	}
}

func getPlexOAuthPin() (*PinResponse, error) {
	xPlexHeaders := getPlexHeaders()

	requestBody := strings.NewReader("strong=true")
	request, err := http.NewRequest("POST", "https://plex.tv/api/v2/pins", requestBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range xPlexHeaders {
		request.Header.Set(key, value)
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var pinResponse PinResponse
	err = json.NewDecoder(response.Body).Decode(&pinResponse)
	if err != nil {
		return nil, err
	}

	return &pinResponse, nil
}

func getUrl(code string) string {
	xPlexHeaders := getPlexHeaders()
	oauthParams := url.Values{
		"clientID":                          {xPlexHeaders["X-Plex-Client-Identifier"]},
		"context[device][product]":          {xPlexHeaders["X-Plex-Product"]},
		"context[device][version]":          {xPlexHeaders["X-Plex-Version"]},
		"context[device][platform]":         {xPlexHeaders["X-Plex-Platform"]},
		"context[device][platformVersion]":  {xPlexHeaders["X-Plex-Platform-Version"]},
		"context[device][device]":           {xPlexHeaders["X-Plex-Device"]},
		"context[device][deviceName]":       {xPlexHeaders["X-Plex-Device-Name"]},
		"context[device][model]":            {xPlexHeaders["X-Plex-Model"]},
		"context[device][screenResolution]": {xPlexHeaders["X-Plex-Device-Screen-Resolution"]},
		"context[device][layout]":           {"desktop"},
		"code":                              {code},
	}

	return "https://app.plex.tv/auth/#!?" + oauthParams.Encode()
}

func getTokenIfAuthenticated(pin int) (*TokenResponse, error) {
	url := "https://plex.tv/api/v2/pins/" + strconv.Itoa(pin)

	headers := getPlexHeaders()

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var tokenResponse TokenResponse
	err = json.NewDecoder(response.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, err
	}

	return &tokenResponse, nil
}
