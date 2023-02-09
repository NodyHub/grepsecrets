package main

import (
	"bufio"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"

	"gopkg.in/yaml.v2"
)

var (
	//go:embed secrets-patterns-db/db/rules-stable.yml
	embeddedRules []byte
)

type cliParameter struct {
	ExternalRules bool
	Recursive     bool
	ListFilepath  bool
	ListPatterns  bool
	Verbose       bool
}

type SecretRegex struct {
	Title string
	Regex regexp.Regexp
}

var SearchPatterns []SecretRegex

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

func parseRegex(ARGS cliParameter) {
	if ARGS.ExternalRules {

		// Parse rules from external repo

		type PatternStruct struct {
			Name       string `yaml:"name"`
			Regex      string `yaml:"regex"`
			Confidence string `yaml:"confidence"`
		}

		type PatternsList struct {
			PatElem PatternStruct `yaml:"pattern"`
		}

		type PatternsFile struct {
			Patterns []PatternsList `yaml:"patterns"`
		}

		var externalPatternsFile PatternsFile
		log.Printf("Loaded bytes: %v\n", len(embeddedRules))
		err := yaml.Unmarshal(embeddedRules, &externalPatternsFile)
		if err != nil {
			panic(err)
		}
		for _, pattern := range externalPatternsFile.Patterns {
			re, err := regexp.Compile(pattern.PatElem.Regex)
			if err != nil {
				log.Printf("Error compilingregex: %v\n", err.Error())
			} else {
				SearchPatterns = append(SearchPatterns,
					SecretRegex{
						Title: pattern.PatElem.Name,
						Regex: *re,
					},
				)
			}
		}

	} else {

		// Parse static coded rules
		SearchPatterns = make([]SecretRegex, 0, len(KnownRegex))
		for title, regex := range KnownRegex {
			re, err := regexp.Compile(regex)
			if err != nil {
				log.Printf("Error compilingregex: %v\n", err.Error())
			} else {
				SearchPatterns = append(SearchPatterns,
					SecretRegex{
						Title: title,
						Regex: *re,
					},
				)

			}
		}
	}
}

func readDirectory(ARGS cliParameter, directoryName string) {
	log.Printf("Scan directory %v\n", directoryName)
	files, err := ioutil.ReadDir(directoryName)
	if err != nil {
		log.Printf("ERROR: %v\n", err)
		return
	}
	for _, file := range files {
		analyzeFile(ARGS, fmt.Sprintf("%v/%v", directoryName, file.Name()))
	}
}

// analyzeFile reads file line-by-line and assume that they are all urls
func analyzeFile(ARGS cliParameter, inputFile string) {

	file, err := os.Open(inputFile)
	if err != nil {
		log.Printf("ERROR: %v", err)
		return
	}
	defer file.Close()

	// This returns an *os.FileInfo type
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("ERROR: %v", err)
		return
	}

	// IsDir is short for fileInfo.Mode().IsDir()
	if fileInfo.IsDir() && ARGS.Recursive {
		readDirectory(ARGS, inputFile)
	} else {
		// Read while file content
		log.Printf("Reading %s", inputFile)
		rawLines, err := os.ReadFile(inputFile)
		if err != nil {
			log.Printf("ERROR: %v", err)
			return
		}

		lines := string(rawLines)
		log.Printf("Read %v lines", len(strings.Split(lines, "\n")))
		if success, match := checkLines(lines); success {
			if ARGS.ListFilepath {
				fmt.Println(inputFile)
				return
			} else {
				fmt.Println(match)
			}
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
		if success, match := checkLines(line); success {
			matches = append(matches, match)
		}
	}
	for _, match := range matches {
		fmt.Println(match)
	}
}

func checkLines(line string) (bool, string) {
	for _, pattern := range SearchPatterns {
		if found := pattern.Regex.FindString(line); len(found) > 0 {
			log.Printf("Found %s (Pattern: %v) !!! \n", pattern.Title, pattern.Regex.String())
			return true, found
		}
	}
	return false, ""
}

const (
	usage = `usage: %s [flags] [files]
grepsecrets searches for secrets in provided input.

Default reads from stdin

Options:
--------
[files] provide the files.
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
	recursive := flag.Bool("r", false, "Recurisive directory traversal")
	listFilepath := flag.Bool("l", false, "List path to file that contain secrets")
	externalRules := flag.Bool("x", false, "Use external rule for analysis")
	listPatterns := flag.Bool("p", false, "List patterns")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Usage = func() {
		log.SetFlags(0)
		log.Printf(usage, os.Args[0])
		flag.PrintDefaults()
		log.Printf("\n%s@%s %v\n", fifiSource, version, buildTime)
	}
	flag.Parse()
	input := flag.Args()
	ARGS := cliParameter{
		ExternalRules: *externalRules,
		Recursive:     *recursive,
		ListFilepath:  *listFilepath,
		ListPatterns:  *listPatterns,
		Verbose:       *verbose,
	}

	if ARGS.Verbose {
		log.SetOutput(flag.CommandLine.Output())
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// Read patterns from embedded FS
	parseRegex(ARGS)
	log.Printf("Loaded %v pattern\n", len(SearchPatterns))

	if *listPatterns {
		// Collect titles and sort them
		titles := make([]string, 0, len(SearchPatterns))
		for _, pattern := range SearchPatterns {
			titles = append(titles, fmt.Sprintf("%v: `%v`", pattern.Title, pattern.Regex.String()))
		}
		sort.Strings(titles)

		// Print title and patterns
		for _, title := range titles {
			fmt.Println(title)
		}

	} else {

		// Analyze input
		if len(input) == 0 {
			log.Println("reading from stdin...")
			readFromStdin()
		} else {
			// Read files
			for _, ifile := range input {
				analyzeFile(ARGS, ifile)
			}
		}
	}

}
