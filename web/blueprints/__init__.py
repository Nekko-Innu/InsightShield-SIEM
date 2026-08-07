# web/blueprints/
# One module per group of routes. Every URL rule is byte-identical to what
# app.py served before the split — only endpoint names gained a blueprint
# prefix — so nginx, scripts/smoke_test.sh and existing bookmarks are
# unaffected.
