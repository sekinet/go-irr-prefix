package prefix

import "time"
import "regexp"
import "github.com/domainr/whois"

//
var Interval = 5 * time.Second

var WhoisServers = [...]string {
		"whois.altdb.net", "whois.in.bell.ca", "irr.bboi.net",
		"jpirr.nic.ad.jp", "whois.nestegg.net", "rr.ntt.net", "whois.openface.ca",
		"rrdb.access.net", "whois.radb.net", "rr.telstraglobal.net",
		"whois.rg.net", "rr.risq.net", "whois.rogerstelecom.net","whois.bgp.net.br",
	}

type AsInfo struct {
	AsNum string
	PrefixList []string
	ReferencedIrr []string
}

func (asinfo *AsInfo) ExtractPrefixCidr(prefixSlice [][]string) {
  for _, v := range prefixSlice {
    asinfo.PrefixList = append(asinfo.PrefixList, v[0])
  }
}

func FindCidr(input string) [][]string {
  numBlock := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
  subnet := "(3[0-2]|[1-2][0-9]|[0-9])"
  regexPattern := numBlock + "\\." + numBlock + "\\." + numBlock + "\\." + numBlock + "/" + subnet
  regEx := regexp.MustCompile(regexPattern)
  return regEx.FindAllStringSubmatch(input, -1)
}

func Dedupe(arr []string) []string {
  m := make(map[string]bool)
  uniq := []string{}
  for _, v := range arr {
    if !m[v] {
      m[v] = true
      uniq = append(uniq, v)
    }
  }
  return uniq
}

func NewWhoisRequestInfo(query string, host string) (*whois.Request, error) {
  req := &whois.Request{Query: query, Host: host}
  if err := req.Prepare(); err != nil {
    return nil, err
  }
  return req, nil
}

var NewClient = whois.NewClient
