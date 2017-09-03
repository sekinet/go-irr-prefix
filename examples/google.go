package main

import "os"
import "fmt"
import "sort"
import "github.com/sekinet/go-irr-prefix/route-prefix"

func main() {
  whoisClient := prefix.NewClient(prefix.Interval)

  Google := &prefix.AsInfo{AsNum: "15169"}
  fmt.Println(Google)
  query := "!gas" + Google.AsNum

  for _, v := range prefix.WhoisServers {
    // Define request query content and IRR host.
    requestInfo, err := prefix.NewWhoisRequestInfo(query, v)
    if err != nil {
      fmt.Println("Received error from whois.Request: ", err)
      os.Exit(1)
    }

    // Actual fetch func with requestInfo.
    res, _ := whoisClient.Fetch(requestInfo)
    if err != nil {
      fmt.Println("Received error from whois.Fetch: ", err)
      os.Exit(1)
    }
    Google.ExtractPrefixCidr(prefix.FindCidr(res.String()))
  }

	// Remove duplicated prefix.
  Google.PrefixList = prefix.Dedupe(Google.PrefixList)
  sort.Strings(Google.PrefixList)
  for _, v := range Google.PrefixList {
    // Print as juniper prefix-list format.
    fmt.Printf("set policy-options prefix-list AS%s %s\n",Google.AsNum, v)
  }
}
