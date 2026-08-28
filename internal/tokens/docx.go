package tokens

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html"
	"time"
)

// GenerateDocx builds a Word document that calls home when it is opened.
//
// The mechanism is an attached template with an external target: Word resolves
// it on open, before any content is rendered, without the "enable content"
// prompt that macros trigger. That makes it the most reliable document canary
// there is -- and, unlike a macro, the file contains no executable content at
// all, so it cannot harm whoever opens it.
func GenerateDocx(t *Token, title, body string) ([]byte, error) {
	if t.Value == "" {
		return nil, fmt.Errorf("tokens: token %s has no callback URL", t.ID)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name, content string) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(content))
		return err
	}

	files := []struct{ name, content string }{
		{"[Content_Types].xml", contentTypesXML},
		{"_rels/.rels", rootRelsXML},
		{"word/document.xml", documentXML(title, body)},
		{"word/settings.xml", settingsXML},
		// This is the canary: an external relationship Word fetches on open.
		{"word/_rels/settings.xml.rels", settingsRelsXML(t.Value)},
		{"docProps/core.xml", corePropsXML(title)},
	}
	for _, f := range files {
		if err := add(f.name, f.content); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>`

const rootRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>`

const settingsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:attachedTemplate r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
<w:defaultTabStop w:val="720"/>
</w:settings>`

func settingsRelsXML(url string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="` +
		html.EscapeString(url) + `" TargetMode="External"/>
</Relationships>`
}

func documentXML(title, body string) string {
	para := func(text, style string) string {
		return `<w:p><w:pPr><w:pStyle w:val="` + style + `"/></w:pPr><w:r><w:t xml:space="preserve">` +
			html.EscapeString(text) + `</w:t></w:r></w:p>`
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		para(title, "Heading1") + para(body, "Normal") +
		`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr></w:body></w:document>`
}

func corePropsXML(title string) string {
	now := time.Now().UTC().Format(time.RFC3339)
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>` + html.EscapeString(title) + `</dc:title>
<dc:creator>Finance</dc:creator>
<cp:lastModifiedBy>Finance</cp:lastModifiedBy>
<dcterms:created xsi:type="dcterms:W3CDTF">` + now + `</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">` + now + `</dcterms:modified>
</cp:coreProperties>`
}
