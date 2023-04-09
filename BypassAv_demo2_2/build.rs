fn main() {
    cc::Build::new()
        // .file("1.c")
        .file("1.x64.asm")
        .compile("sys");
}
