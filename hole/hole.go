package hole

import (
	"html/template"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	min "github.com/tdewolff/minify/v2/minify"
)

type Hole struct {
	Prev, Next, ID, Name, Category, CategoryColor, CategoryIcon string
	Preamble                                                    template.HTML
	Links                                                       []struct{ Name, URL string }
}

var (
	ByID = map[string]Hole{}
	List []Hole
)

func init() {
	var holesTOML map[string]Hole

	if _, err := toml.DecodeFile("holes.toml", &holesTOML); err != nil {
		panic(err)
	}

	for name, hole := range holesTOML {
		hole.Name = name
		hole.ID = strings.ToLower(
			strings.ReplaceAll(strings.ReplaceAll(name, "’", ""), " ", "-"))

		// Minify HTML
		if html, err := min.HTML(string(hole.Preamble)); err != nil {
			panic(err)
		} else {
			hole.Preamble = template.HTML(html)
		}

		List = append(List, hole)
	}

	sort.Slice(List, func(i, j int) bool { return List[i].Name < List[j].Name })

	for i, hole := range List {
		if i == 0 {
			List[i].Prev = List[len(List)-1].ID
		} else {
			List[i].Prev = List[i-1].ID
		}

		if i == len(List)-1 {
			List[i].Next = List[0].ID
		} else {
			List[i].Next = List[i+1].ID
		}

		switch hole.Category {
		case "Art":
			List[i].CategoryColor = "red"
			List[i].CategoryIcon = "\uf53f"
		case "Computing":
			List[i].CategoryColor = "orange"
			List[i].CategoryIcon = "\uf544"
		case "Gaming":
			List[i].CategoryColor = "yellow"
			List[i].CategoryIcon = "\uf11b"
		case "Mathematics":
			List[i].CategoryColor = "green"
			List[i].CategoryIcon = "\uf698"
		case "Sequence":
			List[i].CategoryColor = "blue"
			List[i].CategoryIcon = "\uf162"
		case "Transform":
			List[i].CategoryColor = "purple"
			List[i].CategoryIcon = "\uf074"
		}

		ByID[hole.ID] = List[i]
	}
}
