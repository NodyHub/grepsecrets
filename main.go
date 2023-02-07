package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
)

type cliParameter struct {
	Recursive bool
	Verbose   bool
}

type SecretRegex struct {
	Title string
	Regex string
}

var KnownRegex = map[string]string{
	"Cloudinary":                    `cloudinary://.*`,
	"Firebase URL":                  `.*firebaseio\.com`,
	"Slack Token":                   `(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,
	"RSA private key":               `-----BEGIN RSA PRIVATE KEY-----`,
	"SSH (DSA) private key":         `-----BEGIN DSA PRIVATE KEY-----`,
	"SSH (EC) private key":          `-----BEGIN EC PRIVATE KEY-----`,
	"PGP private key block":         `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
	"Open SSH Private Key":          `-----BEGIN OPENSSH PRIVATE KEY-----`,
	"Amazon AWS Access Key ID":      `AKIA[0-9A-Z]{16}`,
	"Amazon MWS Auth Token":         `amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
	"AWS API Key":                   `AKIA[0-9A-Z]{16}`,
	"Facebook Access Token":         `EAACEdEose0cBA[0-9A-Za-z]+`,
	"Facebook OAuth":                `[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`,
	"GitHub":                        `[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]`,
	"Generic API Key":               `[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]`,
	"Generic Secret":                `[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]`,
	"Google API Key":                `AIza[0-9A-Za-z\\-_]{35}`,
	"Google Cloud Platform API Key": `AIza[0-9A-Za-z\\-_]{35}`,
	"Google Cloud Platform OAuth":   `[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
	"Google Drive API Key":          `AIza[0-9A-Za-z\\-_]{35}`,
	"Google Drive OAuth":            `[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
	"Google (GCP) Service-account":  `\"type\": \"service_account\"`,
	"Google Gmail API Key":          `AIza[0-9A-Za-z\\-_]{35}`,
	"Google Gmail OAuth":            `[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
	"Google OAuth Access Token":     `ya29\\.[0-9A-Za-z\\-_]+`,
	"Google YouTube API Key":        `AIza[0-9A-Za-z\\-_]{35}`,
	"Google YouTube OAuth":          `[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`,
	"Heroku API Key":                `[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
	"MailChimp API Key":             `[0-9a-f]{32}-us[0-9]{1,2}`,
	"Mailgun API Key":               `key-[0-9a-zA-Z]{32}`,
	"Password in URL":               `[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]`,
	"PayPal Braintree Access Token": `access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`,
	"Picatic API Key":               `sk_live_[0-9a-z]{32}`,
	"Slack Webhook":                 `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
	"Stripe API Key":                `sk_live_[0-9a-zA-Z]{24}`,
	"Stripe Restricted API Key":     `rk_live_[0-9a-zA-Z]{24}`,
	"Square Access Token":           `sq0atp-[0-9A-Za-z\\-_]{22}`,
	"Square OAuth Secret":           `sq0csp-[0-9A-Za-z\\-_]{43}`,
	"Twilio API Key":                `SK[0-9a-fA-F]{32}`,
	"Twitter Access Token":          `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}`,
	"Twitter OAuth":                 `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]`,
}

// filter function for slices
func filter(ss []string, test func(string) bool) (ret []string) {
	for _, s := range ss {
		if test(s) {
			ret = append(ret, s)
		}
	}

	return
}

// analyzeFile reads file line-by-line and assume that they are all urls
func analyzeFile(inputFile string) {
	// Read while file content
	log.Printf("Reading %s", inputFile)
	rawLines, err := os.ReadFile(inputFile)
	if err != nil {
		return
	}

	lines := strings.Split(string(rawLines), "\n")
	log.Printf("Read %v lines", len(lines))
	for _, line := range lines {
		if checkLine(line) {
			fmt.Println(line)
		}
	}
}

// readFromStdin reads from stdin until eol
func readFromStdin() {
	var matches []string
	in := bufio.NewReader(os.Stdin)
	for {
		s, err := in.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return
			}
			break
		}

		line := strings.TrimSpace(s)
		if checkLine(line) {
			matches = append(matches, line)
		}
	}
	for _, match := range matches {
		fmt.Println(match)
	}
}

func checkLine(line string) bool {
	for title, regexPattern := range KnownRegex {
		matched, _ := regexp.MatchString(regexPattern, line)
		if matched {
			log.Printf("Found %s !!!\n", title)
			return true
		}
	}
	return false
}

const (
	usage = `usage: %s [files]
grepsecrets searches for secrets in provided input.

Default reads from stdin

Options:
--------
[files] provide the urls in files.
`
)

func main() {

	// Read Build Time infos
	bi, _ := debug.ReadBuildInfo()
	buildTime := ""
	for _, v := range bi.Settings {
		if v.Key == "vcs.time" {
			buildTime = v.Value
		}
	}
	fifiSource := bi.Main.Path
	version := bi.Main.Version

	// Read cli param
	// recursive := flag.Bool("v", false, "Recurisive directory traversal")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Usage = func() {
		log.SetFlags(0)
		log.Printf(usage, os.Args[0])
		flag.PrintDefaults()
		log.Printf("\n%s@%s %v\n", fifiSource, version, buildTime)
	}
	flag.Parse()
	input := flag.Args()

	if *verbose {
		log.SetOutput(flag.CommandLine.Output())
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// Analyze input
	if len(input) == 0 {
		log.Println("reading from stdin...")
		readFromStdin()
	} else {
		// Read files
		for _, ifile := range input {
			analyzeFile(ifile)
		}
	}

}
