# block 0.1.6 (vendored, patched)

A vendored copy of the crates.io [`block`](https://crates.io/crates/block)
crate (MIT, by Steven Sheldon), wired in via `[patch.crates-io]` in the
workspace `Cargo.toml`. It reaches us transitively on macOS through
iced → wgpu → metal, and upstream is archived.

One change relative to the published 0.1.6 source: `Class`, the type of the
`_NSConcreteStackBlock` extern static, is an opaque zero-sized struct instead
of an uninhabited enum. A static of uninhabited type is unsound
(<https://github.com/rust-lang/rust/issues/74840>) and a future-incompat
hard-error-to-be; this patch is what silences that notice for the workspace.

Drop this vendored copy (and the `[patch.crates-io]` entry) as soon as the
dependency chain stops pulling `block` in — e.g. once wgpu's metal backend
moves to `objc2`/`block2`.
