#[test]
fn test_gpu_sha256() {
    use ocl::{Buffer, MemFlags, ProQue};

    println!("\n=== GPU SHA256 测试 ===\n");

    // 测试向量: "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let test_input: Vec<u8> = b"abc".to_vec();
    let expected: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    print!("Input: ");
    for byte in &test_input {
        print!("{}", *byte as char);
    }
    println!();

    print!("Expected SHA256: ");
    for byte in &expected {
        print!("{:02x}", byte);
    }
    println!();

    // 读取SHA256内核
    let sha256_source = std::fs::read_to_string("kernels/crypto/sha256.cl").unwrap();
    let test_source = r#"
__kernel void test_sha256(__global const uchar* input, uint input_len, __global uchar* output) {
    // 先将__global数据复制到__private
    uchar input_local[64];
    for (uint i = 0; i < input_len && i < 64; i++) {
        input_local[i] = input[i];
    }
    // 使用__private缓冲区接收SHA256结果
    uchar output_local[32];
    sha256(input_local, input_len, output_local);
    // 复制回__global
    for (uint i = 0; i < 32; i++) {
        output[i] = output_local[i];
    }
}
"#;

    let full_source = format!("{}\n{}", sha256_source, test_source);

    // 创建ProQue
    let proque = ProQue::builder().src(full_source).dims(1).build().unwrap();

    // 创建缓冲区
    let input_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .len(test_input.len())
        .flags(MemFlags::READ_ONLY)
        .build()
        .unwrap();

    let output_buffer = Buffer::<u8>::builder()
        .queue(proque.queue().clone())
        .len(32)
        .flags(MemFlags::WRITE_ONLY)
        .build()
        .unwrap();

    // 写入输入数据

    input_buffer.cmd().write(&test_input).enq().unwrap();

    // 创建并执行kernel
    let kernel = proque
        .kernel_builder("test_sha256")
        .arg(&input_buffer)
        .arg(test_input.len() as u32)
        .arg(&output_buffer)
        .build()
        .unwrap();

    unsafe {
        kernel.cmd().enq().unwrap();
    }

    // 读取输出
    let mut gpu_output = vec![0u8; 32];

    output_buffer.cmd().read(&mut gpu_output).enq().unwrap();

    print!("GPU SHA256:      ");
    for byte in &gpu_output {
        print!("{:02x}", byte);
    }
    println!();

    if gpu_output == expected {
        println!("\n✅ GPU SHA256计算正确！");
    } else {
        println!("\n❌ GPU SHA256计算错误！");
        println!("\n逐字节对比：");
        for i in 0..32 {
            if gpu_output[i] != expected[i] {
                println!(
                    "  字节{}: GPU={:02x}, 期望={:02x} ❌",
                    i, gpu_output[i], expected[i]
                );
            }
        }
    }
}
