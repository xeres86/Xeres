// Host page — index.html generation (branded shell vs full-bleed, app.css <link>).
use crate::frontend::parser::{ViewNode, XeresProgram};

// ------------------------------------------------------------------ index.html

/// Generate the host page. A screen whose root carries an explicit `style`
/// "owns the canvas": it renders full-bleed on a neutral page (no centered
/// card, logo, or purple gradient). Unstyled apps keep the branded shell.
/// `has_css` (spec 26) links the generated `static/app.css` stylesheet when the
/// app declares a `theme` or a named `style` — omitted otherwise, so a plain
/// app's `index.html` is byte-identical to before spec 26.
pub(super) fn gen_index(program: &XeresProgram, has_css: bool) -> String {
    let mut out = String::new();
    let first = program.screens.iter().find(|s| !s.is_component && s.params.is_empty());
    let bleed = first.map(screen_is_bleed).unwrap_or(false);

    if bleed {
        // Full-bleed: just the mount point on a neutral page.
        out.push_str(&inject_css_link(INDEX_HEAD_BLEED, has_css));
        out.push_str("<div id=\"app\"></div>");
        out.push_str(
            // Absolute path so a deep link to a nested route (e.g. `/post/123`)
            // still resolves the bundle (a relative `./client.js` would 404 as
            // `/post/client.js`).
            "<script type=\"module\" src=\"/client.js\"></script>",
        );
        out.push_str("</body></html>");
        return out;
    }

    out.push_str(&inject_css_link(INDEX_HEAD, has_css));
    if first.is_some() {
        out.push_str("<div id=\"app\"></div>");
    } else {
        out.push_str("<div id=\"app\" class=\"hint\">Add a <code>ui screen Name { … }</code> to app.xrs.</div>");
    }
    out.push_str("<footer>powered by <b>Xeres</b> · tier-safe web · zero framework runtime</footer>");
    out.push_str("</main>");
    if first.is_some() {
        out.push_str(
            // Absolute path so a deep link to a nested route (e.g. `/post/123`)
            // still resolves the bundle (a relative `./client.js` would 404 as
            // `/post/client.js`).
            "<script type=\"module\" src=\"/client.js\"></script>",
        );
    }
    out.push_str("</body></html>");
    out
}

/// A screen "owns the canvas" when one of its top-level view nodes is a styled
/// element — the dev has taken explicit control of the page's look.
fn screen_is_bleed(sc: &crate::frontend::parser::ScreenNode) -> bool {
    sc.body
        .iter()
        .any(|n| matches!(n, ViewNode::Element { style: Some(_), .. }))
}

/// Insert the `app.css` `<link>` right before `</head>` (spec 26). A no-op
/// when the app has no theme/style — so an unstyled app's head is untouched.
fn inject_css_link(head: &str, has_css: bool) -> String {
    if !has_css {
        return head.to_string();
    }
    head.replacen("</head>", "<link rel=\"stylesheet\" href=\"/app.css\">\n</head>", 1)
}

const INDEX_HEAD: &str = include_str!("../../../runtime/index_head.html");

// Full-bleed host page for screens that style their own root. No centered card,
// no logo/footer, no purple gradient — the screen controls the whole viewport.
// Nested unstyled `row`/`column` still get sensible flex defaults; `button` and
// `input` get neutral (theme-agnostic) styling that inline `style` can override.
const INDEX_HEAD_BLEED: &str = include_str!("../../../runtime/index_head_bleed.html");
