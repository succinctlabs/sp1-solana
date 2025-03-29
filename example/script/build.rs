use sp1_build::BuildArgs;

fn main() {
    sp1_build::build_program_with_args(
        "../sp1-program",
        BuildArgs {
            ..Default::default()
        },
    );
}
