package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

var domainRegex = regexp.MustCompile(`([a-zA-Z0-9-]+)\.([a-z0-9-]+)?\.?s3[\.-]([a-z0-9-]+)?\.?amazonaws\.com`)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Please provide a URL or file as an argument")
		return
	}

	input := os.Args[1]

	// Check if the argument is a file
	if _, err := os.Stat(input); err == nil {
		// Open the file
		f, err := os.Open(input)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer f.Close()

		// Read the file line by line
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// Set the URL variable as the scanned line
			url := scanner.Text()

			// Send the URL to the grabber function
			grabber(url)
		}
		if err := scanner.Err(); err != nil {
			fmt.Println(err)
		}
	} else {
		// Set the URL variable as the input argument
		url := input

		// Send the URL to the grabber function
		grabber(url)
	}
}

func grabber(url2 string) {

	u, err := url.Parse(url2)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Get the Content-Security-Policy-Report-Only header, if present
	headerValue := resp.Header.Get("Content-Security-Policy")

	domains := domainRegex.FindAllString(headerValue, -1)

	// Create a map to store unique domains
	uniqueDomains := make(map[string]bool)

	// Iterate over the list of domains and add them to the map
	for _, domain := range domains {
		uniqueDomains[domain] = true
	}

	// Open file for saving
	file, _ := os.OpenFile("csp-doms.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer file.Close()

	// Iterate over the unique domains and print them to the command line and file
	for domain := range uniqueDomains {
		fmt.Println(domain)
		file.WriteString(domain + "\n")
	}

}
