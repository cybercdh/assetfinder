package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func fetchMerkleMap(domain string) ([]string, error) {
	var output []string
	apiURL := "https://api.merklemap.com/v1/search"
	authToken := os.Getenv("MERKLEMAP_KEY")

	page := 0
	for {
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return output, err
		}

		query := req.URL.Query()
		query.Add("query", "."+domain)
		query.Add("page", fmt.Sprintf("%d", page))
		req.URL.RawQuery = query.Encode()
		req.Header.Add("Authorization", "Bearer "+authToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return output, err
		}
		defer resp.Body.Close()

		var response struct {
			Results []struct {
				Hostname string `json:"hostname"`
			} `json:"results"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return output, err
		}

		if len(response.Results) == 0 {
			break
		}

		for _, result := range response.Results {
			output = append(output, result.Hostname)
		}
		page++
	}

	return output, nil
}
