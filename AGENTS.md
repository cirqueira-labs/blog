# Blog — Cirqueira Dev

## Stack
- **SSG**: [Marmite](https://github.com/rochacbruno/marmite) (Rust, single binary)
- **No JS framework**: no package.json, no pnpm/npm
- **Deploy**: GitHub Actions → GitHub Pages (push to `main` triggers auto-build + deploy)

## Commands
```bash
# Build
marmite . site

# Dev server (auto-reload)
marmite . site --serve --watch

# New page (content/pagina.md → pagina.html)
marmite . --new "Titulo" -p

# New blog post (content/YYYY-MM-DD-titulo.md)
marmite . --new "Titulo" -t "tag1,tag2"
```

## Project structure
- `content/*.md` — pages and posts. Date-prefixed = blog post.
- `content/_*.md` — layout fragments: `_hero.md`, `_comments.md`, `_announce.md`, `_markdown_footer.md`, `_markdown_header.md`, `_404.md`
- `marmite.yaml` — site config (menu, footer, extra, colorscheme)
- `custom.css` / `custom.js` — style/script overrides
- `site/` — generated output (build artifact, not tracked)

## Adding a page
1. Create `content/slug.md` with `# Title` heading
2. Add menu entry in `marmite.yaml` menu section:
   ```yaml
   - - Label
     - slug.html
   ```
3. Rebuild

## Comments
Giscus (GitHub Discussions) via `content/_comments.md`.
- Repo: `cirqueira-labs/blog`, category: "General"
- Comments only appear on pages/posts, not on listing pages

## Bash prefix
Always prefix shell commands with `rtk` (e.g. `rtk grep`, `rtk ls`).

## Notes
- `.gitignore` added with safe defaults (secrets, OS files, keys)
- `site/` is NOT tracked in git anymore — it is a build artifact only
- Changes pushed to `main` auto-deploy via `.github/workflows/main.yaml`
- No external comment DB — comments stored as GitHub Discussions

## Security
- Marmite version pinned in CI: `cargo install marmite --version 0.2.6`
- Giscus uses SRI (`integrity` attribute) for CDN script
- CSP meta tag injected via `_markdown_header.md`
- `custom.js` and `custom.css` modifications MUST be code-reviewed (they inject into every page)
