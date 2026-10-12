// Code generated from packages/better-auth/src/api/routes/error.ts (v1.7.7) by a converter
// script; the markup is kept byte-identical to upstream.

package betterauth

import "strings"

func renderErrorPage(custom *ErrorPageCustomization, code, description string) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Error</title>
    <style>
      * {
        box-sizing: border-box;
      }
      body {
        font-family: `)
	b.WriteString(pageVal(custom, "font", "defaultFamily", "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"))
	b.WriteString(`;
        background: `)
	b.WriteString(pageVal(custom, "colors", "background", "var(--background)"))
	b.WriteString(`;
        color: var(--foreground);
        margin: 0;
      }
      :root,
      :host {
        --spacing: 0.25rem;
        --container-md: 28rem;
        --text-sm: `)
	b.WriteString(pageVal(custom, "size", "textSm", "0.875rem"))
	b.WriteString(`;
        --text-sm--line-height: calc(1.25 / 0.875);
        --text-2xl: `)
	b.WriteString(pageVal(custom, "size", "text2xl", "1.5rem"))
	b.WriteString(`;
        --text-2xl--line-height: calc(2 / 1.5);
        --text-4xl: `)
	b.WriteString(pageVal(custom, "size", "text4xl", "2.25rem"))
	b.WriteString(`;
        --text-4xl--line-height: calc(2.5 / 2.25);
        --text-6xl: `)
	b.WriteString(pageVal(custom, "size", "text6xl", "3rem"))
	b.WriteString(`;
        --text-6xl--line-height: 1;
        --font-weight-medium: 500;
        --font-weight-semibold: 600;
        --font-weight-bold: 700;
        --default-transition-duration: 150ms;
        --default-transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
        --radius: `)
	b.WriteString(pageVal(custom, "size", "radiusSm", "0.625rem"))
	b.WriteString(`;
        --default-mono-font-family: `)
	b.WriteString(pageVal(custom, "font", "monoFamily", "var(--font-geist-mono)"))
	b.WriteString(`;
        --primary: `)
	b.WriteString(pageVal(custom, "colors", "primary", "black"))
	b.WriteString(`;
        --primary-foreground: `)
	b.WriteString(pageVal(custom, "colors", "primaryForeground", "white"))
	b.WriteString(`;
        --background: `)
	b.WriteString(pageVal(custom, "colors", "background", "white"))
	b.WriteString(`;
        --foreground: `)
	b.WriteString(pageVal(custom, "colors", "foreground", "oklch(0.271 0 0)"))
	b.WriteString(`;
        --border: `)
	b.WriteString(pageVal(custom, "colors", "border", "oklch(0.89 0 0)"))
	b.WriteString(`;
        --destructive: `)
	b.WriteString(pageVal(custom, "colors", "destructive", "oklch(0.55 0.15 25.723)"))
	b.WriteString(`;
        --muted-foreground: `)
	b.WriteString(pageVal(custom, "colors", "mutedForeground", "oklch(0.545 0 0)"))
	b.WriteString(`;
        --corner-border: `)
	b.WriteString(pageVal(custom, "colors", "cornerBorder", "#404040"))
	b.WriteString(`;
      }

      button, .btn {
        cursor: pointer;
        background: none;
        border: none;
        color: inherit;
        font: inherit;
        transition: all var(--default-transition-duration)
          var(--default-transition-timing-function);
      }
      button:hover, .btn:hover {
        opacity: 0.8;
      }

      @media (prefers-color-scheme: dark) {
        :root,
        :host {
          --primary: `)
	b.WriteString(pageVal(custom, "colors", "primary", "white"))
	b.WriteString(`;
          --primary-foreground: `)
	b.WriteString(pageVal(custom, "colors", "primaryForeground", "black"))
	b.WriteString(`;
          --background: `)
	b.WriteString(pageVal(custom, "colors", "background", "oklch(0.15 0 0)"))
	b.WriteString(`;
          --foreground: `)
	b.WriteString(pageVal(custom, "colors", "foreground", "oklch(0.98 0 0)"))
	b.WriteString(`;
          --border: `)
	b.WriteString(pageVal(custom, "colors", "border", "oklch(0.27 0 0)"))
	b.WriteString(`;
          --destructive: `)
	b.WriteString(pageVal(custom, "colors", "destructive", "oklch(0.65 0.15 25.723)"))
	b.WriteString(`;
          --muted-foreground: `)
	b.WriteString(pageVal(custom, "colors", "mutedForeground", "oklch(0.65 0 0)"))
	b.WriteString(`;
          --corner-border: `)
	b.WriteString(pageVal(custom, "colors", "cornerBorder", "#a0a0a0"))
	b.WriteString(`;
        }
      }
      @media (max-width: 640px) {
        :root, :host {
          --text-6xl: 2.5rem;
          --text-2xl: 1.25rem;
          --text-sm: 0.8125rem;
        }
      }
      @media (max-width: 480px) {
        :root, :host {
          --text-6xl: 2rem;
          --text-2xl: 1.125rem;
        }
      }
    </style>
  </head>
  <body style="width: 100vw; min-height: 100vh; overflow-x: hidden; overflow-y: auto;">
    <div
        style="
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 1.5rem;
            position: relative;
            width: 100%;
            min-height: 100vh;
            padding: 1rem;
        "
        >
`)
	if !pageFlag(custom, "disableBackgroundGrid") {
		b.WriteString(`
      <div
        style="
          position: absolute;
          inset: 0;
          background-image: linear-gradient(to right, `)
		b.WriteString(pageVal(custom, "colors", "gridColor", "var(--border)"))
		b.WriteString(` 1px, transparent 1px),
            linear-gradient(to bottom, `)
		b.WriteString(pageVal(custom, "colors", "gridColor", "var(--border)"))
		b.WriteString(` 1px, transparent 1px);
          background-size: 40px 40px;
          opacity: 0.6;
          pointer-events: none;
          width: 100vw;
          height: 100vh;
        "
      ></div>
      <div
        style="
          position: absolute;
          inset: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          background: `)
		b.WriteString(pageVal(custom, "colors", "background", "var(--background)"))
		b.WriteString(`;
          mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          -webkit-mask-image: radial-gradient(ellipse at center, transparent 20%, black);
          pointer-events: none;
        "
      ></div>
`)
	}
	b.WriteString(`

<div
  style="
    position: relative;
    z-index: 10;
    border: 2px solid var(--border);
    background: `)
	b.WriteString(pageVal(custom, "colors", "cardBackground", "var(--background)"))
	b.WriteString(`;
    padding: 1.5rem;
    max-width: 42rem;
    width: 100%;
  "
>
    `)
	if !pageFlag(custom, "disableCornerDecorations") {
		b.WriteString(`
        <!-- Corner decorations -->
        <div
          style="
            position: absolute;
            top: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            top: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-top: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>
  
        <div
          style="
            position: absolute;
            bottom: -2px;
            left: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-left: 4px solid var(--corner-border);
          "
        ></div>
        <div
          style="
            position: absolute;
            bottom: -2px;
            right: -2px;
            width: 2rem;
            height: 2rem;
            border-bottom: 4px solid var(--corner-border);
            border-right: 4px solid var(--corner-border);
          "
        ></div>`)
	}
	b.WriteString(`

        <div style="text-align: center; margin-bottom: 1.5rem;">
          <div style="margin-bottom: 1.5rem;">
            <div
              style="
                display: inline-block;
                border: 2px solid `)
	if pageFlag(custom, "disableTitleBorder") {
		b.WriteString("transparent")
	} else {
		b.WriteString(pageVal(custom, "colors", "titleBorder", "var(--destructive)"))
	}
	b.WriteString(`;
                padding: 0.375rem 1rem;
              "
            >
              <h1
                style="
                  font-size: var(--text-6xl);
                  font-weight: var(--font-weight-semibold);
                  color: `)
	b.WriteString(pageVal(custom, "colors", "titleColor", "var(--foreground)"))
	b.WriteString(`;
                  letter-spacing: -0.02em;
                  margin: 0;
                "
              >
                ERROR
              </h1>
            </div>
            <div
              style="
                height: 2px;
                background-color: var(--border);
                width: calc(100% + 3rem);
                margin-left: -1.5rem;
                margin-top: 1.5rem;
              "
            ></div>
          </div>

          <h2
            style="
              font-size: var(--text-2xl);
              font-weight: var(--font-weight-semibold);
              color: var(--foreground);
              margin: 0 0 1rem;
            "
          >
            Something went wrong
          </h2>

          <div
            style="
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                border: 2px solid var(--border);
                background-color: var(--muted);
                padding: 0.375rem 0.75rem;
                margin: 0 0 1rem;
                flex-wrap: wrap;
                justify-content: center;
            "
            >
            <span
                style="
                font-size: 0.75rem;
                color: var(--muted-foreground);
                font-weight: var(--font-weight-semibold);
                "
            >
                CODE:
            </span>
            <span
                style="
                font-size: var(--text-sm);
                font-family: var(--default-mono-font-family, monospace);
                color: var(--foreground);
                word-break: break-all;
                "
            >
                `)
	b.WriteString(sanitizeHTML(code))
	b.WriteString(`
            </span>
            </div>

          <p
            style="
              color: var(--muted-foreground);
              max-width: 28rem;
              margin: 0 auto;
              font-size: var(--text-sm);
              line-height: 1.5;
              text-wrap: pretty;
            "
          >
            `)
	if description == "" {
		b.WriteString("We encountered an unexpected error. Please try again or return to the home page. If you're a developer, you can find ")
		b.WriteString(`<a href='https://better-auth.com/docs/reference/errors/`)
		b.WriteString(EncodeURIComponent(code))
		b.WriteString(`' target='_blank' rel="noopener noreferrer" style='color: var(--foreground); text-decoration: underline;'>more information about the error</a>.`)
	} else {
		b.WriteString(description)
	}
	b.WriteString(`
          </p>
        </div>

        <div
          style="
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
            justify-content: center;
            flex-wrap: wrap;
          "
        >
          <a
            href="/"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: var(--primary);
                color: var(--primary-foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Go Home
            </div>
          </a>
          <a
            href="https://better-auth.com/docs/reference/errors/`)
	b.WriteString(EncodeURIComponent(code))
	b.WriteString(`?askai=`)
	b.WriteString(EncodeURIComponent("What does the error code " + code + " mean?"))
	b.WriteString(`"
            target="_blank"
            rel="noopener noreferrer"
            style="
              text-decoration: none;
            "
          >
            <div
              style="
                border: 2px solid var(--border);
                background: transparent;
                color: var(--foreground);
                padding: 0.5rem 1rem;
                border-radius: 0;
                white-space: nowrap;
              "
              class="btn"
            >
              Ask AI
            </div>
          </a>
        </div>
      </div>
    </div>
  </body>
</html>`)
	return b.String()
}
