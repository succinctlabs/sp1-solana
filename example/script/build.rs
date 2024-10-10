use sp1_build::build_program;

fn main() {
    // build_program_with_args(
    //     "../sp1-program",
    //     BuildArgs {
    //         output_directory: "../../elf".to_string(),
    //         elf_name: "fibonacci_elf".to_string(),
    //         ..Default::default()
    //     },
    // );
    build_program("../sp1-program");
}
