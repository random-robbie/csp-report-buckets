package main

import (
    "fmt"
    "net/http"
    "os"
    "regexp"
    "strings"
    "crypto/tls"
    "bufio"
)


var domainRegex = regexp.MustCompile(`([a-zA-Z0-9-]+)\.([a-z0-9-]+)?\.?s3\.([a-z0-9-]+)\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com`)


func processURL(url string) {
    // Make the request
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        fmt.Println(err)
        return
    }
    req.Header.Set("User-Agent", "csp-report")
    tr := &http.Transport{
        // ignore bad ssl
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer resp.Body.Close()

    // Extract the domains from the CSP header
    csp := resp.Header.Get("Content-Security-Policy")
    if csp == "" {
        fmt.Println("No CSP header found")
        return
    }
    domains := domainRegex.FindAllString(csp, -1)

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

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: csp-report <url or file>")
        os.Exit(1)
    }

    input := os.Args[1]

    // Input is a text file
    if strings.HasSuffix(input, ".txt") {
        file, err := os.Open(input)
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }
        defer file.Close()

        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
            processURL(scanner.Text())
        }
    } else {
        // Input is a single URL
        processURL(input)
    }
}
