// GPU搜索器 - 参考rust-profanity实现
// 使用ocl库进行OpenCL内核调用

use log::{debug, info};
use ocl::{Buffer, Context, Device, Kernel, Platform, Program, Queue, SpatialDims};

use crate::config::Config;

/// GPU搜索结果
#[derive(Debug, Clone)]
pub struct GpuSearchResult {
    pub mnemonic: String,
    pub password: String,
    pub work_item_index: u32,
}

/// GPU搜索器
pub struct GpuSearcher {
    context: Context,
    queue: Queue,
    program: Program,
    kernel: Kernel,
    word_indices_buffer: Buffer<u32>,
    target_hash_buffer: Buffer<u8>,
    salt_buffer: Buffer<u8>,              // 预计算的salt缓冲区
    result_buffer: Buffer<u32>,
    flag_buffer: Buffer<i32>,
    mnemonic_size: usize,
    salt_len: u32,                        // salt长度
}

impl GpuSearcher {
    /// 创建GPU搜索器
    pub fn new(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        // 根据config的mnemonic_size动态编译内核
        Self::new_with_config(config)
    }
        
    /// 创建GPU搜索器（指定助记词长度）
    pub fn new_with_mnemonic_size(mnemonic_size: usize) -> Result<Self, Box<dyn std::error::Error>> {
        // 创建一个默认config，仅用于初始化
        let config = Config {
            mnemonic_size,
            passwords: vec![],
            target_address: "1KddEkd2fiWuibkSmK1ASBpjpTDjmAZTKs".to_string(), // 默认地址
            word_positions: std::collections::HashMap::new(),
        };
        Self::new_with_config(&config)
    }
    
    /// 创建GPU搜索器（完整配置）
    pub fn new_with_config(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let mnemonic_size = config.mnemonic_size;
        info!("[GPU] 初始化GPU搜索器 (mnemonic_size={})...", mnemonic_size);
        info!("[GPU] 初始化GPU搜索器...");

        // 1. 获取GPU设备
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err("未找到OpenCL平台".into());
        }

        info!("[GPU] 找到 {} 个OpenCL平台", platforms.len());

        // 选择第一个平台的第一个GPU设备
        let mut selected_device: Option<Device> = None;
        let mut selected_platform: Option<Platform> = None;

        for platform in &platforms {
            let devices = Device::list_all(platform)?;
            info!(
                "[GPU] 平台: {:?}, 设备数: {}",
                platform.name(),
                devices.len()
            );

            for device in devices {
                let device_name = device.name()?;
                let device_type = Self::get_device_type(&device)?;
                info!("[GPU]   设备: {} (类型: {})", device_name, device_type);

                // Apple Silicon的GPU可能被识别为GPU或其他类型
                // 优先选择GPU，如果没有则选择第一个设备
                if device_type == "GPU" {
                    selected_device = Some(device);
                    selected_platform = Some(*platform);
                    break;
                } else if selected_device.is_none() {
                    // 保存第一个设备作为备选
                    selected_device = Some(device);
                    selected_platform = Some(*platform);
                }
            }
            if selected_device.is_some()
                && Self::get_device_type(&selected_device.as_ref().unwrap())? == "GPU"
            {
                break;
            }
        }

        let platform = selected_platform.ok_or("未找到OpenCL设备")?;
        let device = selected_device.ok_or("未找到OpenCL设备")?;

        let device_name = device.name()?;
        let device_type = Self::get_device_type(&device)?;
        info!("[GPU] 使用设备: {} (类型: {})", device_name, device_type);

        if device_type != "GPU" {
            info!("[GPU] 警告: 使用的不是GPU设备，性能可能较低");
        }

        // 2. 创建上下文和队列
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()?;

        let queue = Queue::new(&context, device, None)?;

        // 3. 编译内核程序（传入mnemonic_size）
        let program = Self::compile_kernel_program(&context, config.mnemonic_size)?;

        // 4. 预计算目标哈希（优化：在初始化时上传，避免每次search重复上传）
        let target_hash = Self::decode_target_address_static(&config.target_address)?;
        info!("[GPU] 目标哈希已预计算: {:?}", &target_hash[..8]);
        
        // 创建缓冲区
        let config_size = 1024; // 配置缓冲区大小
        let config_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(config_size)
            .build()?;

        let result_size = 1024; // 结果缓冲区大小
        let result_buffer = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(ocl::flags::MEM_READ_WRITE)
            .len(result_size)
            .build()?;

        // 初始化result_buffer为0
        let initial_result = vec![0u32; result_size];
        result_buffer.write(&initial_result).enq()?;

        let flag_buffer = Buffer::<i32>::builder()
            .queue(queue.clone())
            .flags(ocl::flags::MEM_READ_WRITE)
            .len(1)
            .build()?;

        // 创建word_indices缓冲区（足够大的空间，支持干扰词场景）
        let word_indices_buffer = Buffer::<u32>::builder()
            .queue(queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(2048) // 足够大，支持多个干扰词
            .build()?;

        // 创建target_hash缓冲区（20字节）
        let target_hash_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(20)
            .build()?;
        
        // 初始化时即上传目标哈希（优化2）
        target_hash_buffer.write(&target_hash).enq()?;
        debug!("[GPU] 目标哈希已在初始化时上传到GPU");

        // 创建salt缓冲区（最大256字节，支持长passphrase）
        let salt_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(256)
            .build()?;

        // 初始化标志为0
        let initial_flag: Vec<i32> = vec![0];
        flag_buffer.write(&initial_flag).enq()?;

        // 5. 创建内核（6个参数）
        let kernel = Kernel::builder()
            .program(&program)
            .name("btc_address_search")
            .queue(queue.clone())
            .global_work_size(SpatialDims::One(1))
            .arg(&word_indices_buffer) // 参数1: word_indices
            .arg(&target_hash_buffer) // 参数2: target_hash
            .arg(&salt_buffer) // 参数3: salt (预计算)
            .arg(&(0u32)) // 参数4: salt_len
            .arg(&result_buffer) // 参数5: result_buffer
            .arg(&flag_buffer) // 参数6: stats_counter
            .build()?;

        info!("[GPU] GPU搜索器初始化完成");

        Ok(Self {
            context,
            queue,
            program,
            kernel,
            word_indices_buffer,
            target_hash_buffer,
            salt_buffer,
            result_buffer,
            flag_buffer,
            mnemonic_size,
            salt_len: 0,
        })
    }

    /// 获取设备类型
    fn get_device_type(device: &Device) -> Result<String, Box<dyn std::error::Error>> {
        let device_name = device.name()?;
        let name_lower = device_name.to_lowercase();

        if name_lower.contains("gpu")
            || name_lower.contains("graphics")
            || name_lower.contains("nvidia")
            || name_lower.contains("amd")
            || name_lower.contains("radeon")
        {
            Ok("GPU".to_string())
        } else if name_lower.contains("cpu") {
            Ok("CPU".to_string())
        } else {
            Ok("UNKNOWN".to_string())
        }
    }

    /// 编译内核程序
    fn compile_kernel_program(context: &Context, mnemonic_size: usize) -> Result<Program, Box<dyn std::error::Error>> {
        info!("[GPU] 编译内核程序 (MNEMONIC_SIZE={})...", mnemonic_size);

        // 添加MNEMONIC_SIZE宏定义
        let mut source = format!("#define MNEMONIC_SIZE {}\n\n", mnemonic_size);
        
        // 按顺序加载所有内核文件
        let kernel_files = vec![
            "kernels/crypto/sha256.cl",
            "kernels/crypto/ripemd160.cl",
            "kernels/crypto/sha512.cl",
            "kernels/crypto/pbkdf2.cl",
            "kernels/crypto/secp256k1.cl",
            "kernels/bip39/wordlist.cl",
            "kernels/bip39/checksum.cl",
            "kernels/bip39/mnemonic.cl", // BIP32派生路径
            "kernels/search.cl",
        ];

        for file in &kernel_files {
            debug!("[GPU] 加载: {}", file);
            let content = std::fs::read_to_string(file)?;
            source.push_str(&content);
            source.push_str("\n\n");
        }

        info!("[GPU] 内核源代码总长度: {} 字符", source.len());
        info!("[GPU] 编译中...");

        let program = Program::builder().src(&source).build(context)?;

        info!("[GPU] 编译完成");

        Ok(program)
    }

    /// 执行GPU搜索
    pub fn search(
        &mut self,
        config: &Config,
    ) -> Result<Vec<GpuSearchResult>, Box<dyn std::error::Error>> {
        info!("[GPU] 开始搜索...");

        // 1. 准备助记词索引数据
        let word_indices = self.prepare_word_indices(config)?;
        info!("[GPU] 准备 {} 个助记词索引", word_indices.len());

        // 2. 上传word_indices到GPU
        self.word_indices_buffer.write(&word_indices).enq()?;
        debug!("[GPU] 助记词索引已上传到GPU");

        // 3. 目标哈希已在初始化时上传（优化2），无需重复上传
        debug!("[GPU] 目标哈希已在初始化时预上传");

        // 5. 准备salt（预计算 "mnemonic" + passphrase）
        let salt = if !config.passwords.is_empty() {
            let passphrase = config.passwords[0].as_bytes();
            let mut salt = Vec::new();
            salt.extend_from_slice(b"mnemonic");
            salt.extend_from_slice(passphrase);
            salt
        } else {
            b"mnemonic".to_vec()
        };
        
        self.salt_len = salt.len() as u32;
        self.salt_buffer.write(&salt).enq()?;
        debug!("[GPU] Salt已预计算并上传到GPU，长度: {}", self.salt_len);

        // 6. 计算工作项数量
        let work_items = self.calculate_work_items(config);
        info!("[GPU] 工作项数量: {}", work_items);

        if work_items == 0 {
            info!("[GPU] 工作项数量为0，返回空结果");
            return Ok(Vec::new());
        }

        // 7. 更新内核参数（重要：buffer内容已改变，需要重新设置参数）
        self.kernel.set_arg(0, &self.word_indices_buffer)?;
        self.kernel.set_arg(1, &self.target_hash_buffer)?;
        self.kernel.set_arg(2, &self.salt_buffer)?;
        self.kernel.set_arg(3, &self.salt_len)?;
        self.kernel.set_arg(4, &self.result_buffer)?;
        self.kernel.set_arg(5, &self.flag_buffer)?;

        // 8. 启动内核
        let global_work_size = SpatialDims::One(work_items);
        unsafe {
            self.kernel.cmd().global_work_size(global_work_size).enq()?;
        }
        info!("[GPU] 内核已启动");

        // 5. 等待完成
        self.queue.finish()?;
        info!("[GPU] 内核执行完成");

        // 7. 读取结果
        let mut result_data = vec![0u32; 1024];
        self.result_buffer.read(&mut result_data).enq()?;
        self.queue.finish()?;

        // 8. 读取标志
        let mut flag_data = vec![0i32; 1];
        self.flag_buffer.read(&mut flag_data).enq()?;
        self.queue.finish()?;

        info!("[GPU] 找到标志: {}", flag_data[0]);
        info!(
            "[GPU] 结果缓冲区（DEBUG）: magic={:#X}, pubkey_hash={:?}, word_indices={:?}",
            result_data[0],
            &result_data[1..21],
            &result_data[21..33]
        );

        // 8. 解析结果
        let results = self.parse_results(&result_data, config)?;
        info!("[GPU] 找到匹配: {} 个", results.len());

        Ok(results)
    }

    /// 准备配置数据
    fn prepare_config_data(&self, config: &Config) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut data = Vec::new();

        // 助记词大小 (4 bytes)
        data.extend_from_slice(&(config.mnemonic_size as u32).to_le_bytes());

        // 候选词数量 (4 bytes)
        let total_candidates: u32 = config.word_positions.values().map(|v| v.len() as u32).sum();
        data.extend_from_slice(&total_candidates.to_le_bytes());

        // 目标地址哈希 (20 bytes) - 简化处理
        let target_hash = self.decode_target_address(&config.target_address)?;
        data.extend_from_slice(&target_hash);

        // 填充到1024字节
        while data.len() < 1024 {
            data.push(0);
        }

        Ok(data[..1024].to_vec())
    }

    /// 解码目标地址为哈希（静态方法，用于初始化时预计算）
    fn decode_target_address_static(address: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use crate::address::base58check_decode;

        // 使用Base58Check解码Legacy地址，提取pubkey_hash（20字节）
        let pubkey_hash = base58check_decode(address)?;

        if pubkey_hash.len() != 20 {
            return Err(format!(
                "Legacy地址pubkey_hash长度应为20字节，实际为{}字节",
                pubkey_hash.len()
            )
            .into());
        }

        info!(
            "[GPU] Base58Check解码成功，pubkey_hash: {:02x?}",
            &pubkey_hash[..8]
        );
        Ok(pubkey_hash)
    }
    
    /// 解码目标地址为哈希
    fn decode_target_address(&self, address: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Self::decode_target_address_static(address)
    }

    /// 准备助记词索引数组
    /// 
    /// 数据格式：[位置1候选数量, 位置1候选1, 位置1候选2, ..., 位置2候选数量, ...]
    /// GPU根据global_id动态计算每个位置应该选哪个候选词
    fn prepare_word_indices(
        &self,
        config: &Config,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        use crate::mnemonic::Bip39Wordlist;

        let mut indices = Vec::new();

        // 加载单词表
        let wordlist = Bip39Wordlist::load("data/english.txt")?;

        // 遍历每个位置
        for i in 1..=config.mnemonic_size {
            let key = format!("position_{}", i);
            if let Some(candidates) = config.word_positions.get(&key) {
                // 先写入候选词数量
                indices.push(candidates.len() as u32);
                
                // 再写入每个候选词的索引
                for word in candidates {
                    if let Some(index) = wordlist.get_index(word) {
                        indices.push(index as u32);
                    } else {
                        return Err(format!("单词 '{}' 不在BIP39单词表中", word).into());
                    }
                }
            } else {
                // 如果没有候选词，默认为0个（不应该发生）
                indices.push(0);
            }
        }

        info!(
            "[GPU] 准备 {} 个位置的索引，总计 {} 个u32",
            config.mnemonic_size,
            indices.len()
        );
        Ok(indices)
    }

    /// 计算工作项数量
    fn calculate_work_items(&self, config: &Config) -> usize {
        let mut work_items = 1;
        for i in 1..=config.mnemonic_size {
            let key = format!("position_{}", i);
            if let Some(candidates) = config.word_positions.get(&key) {
                work_items *= candidates.len();
            }
        }
        work_items
    }

    /// 解析结果
    fn parse_results(
        &self,
        result_data: &[u32],
        config: &Config,
    ) -> Result<Vec<GpuSearchResult>, Box<dyn std::error::Error>> {
        use crate::mnemonic::Bip39Wordlist;

        let mut results = Vec::new();

        // 第一个元素是结果数量
        let result_count = result_data[0] as usize;

        if result_count == 0 {
            return Ok(results);
        }

        // 加载单词表
        let wordlist = Bip39Wordlist::load("data/english.txt")?;

        // 解析每个结果
        let result_size = self.mnemonic_size + 1; // 助记词索引 + 工作项索引
        for i in 0..result_count {
            let offset = 1 + i * result_size;

            if offset + result_size > result_data.len() {
                break;
            }

            let work_item_index = result_data[offset];

            // 构建助记词字符串
            let mut mnemonic_parts = Vec::new();
            for j in 0..self.mnemonic_size {
                let word_index = result_data[offset + 1 + j] as usize;
                // 从wordlist中获取实际单词
                if let Some(word) = wordlist.get_word(word_index) {
                    mnemonic_parts.push(word.to_string());
                } else {
                    mnemonic_parts.push(format!("unknown_{}", word_index));
                }
            }
            let mnemonic = mnemonic_parts.join(" ");

            let password = if !config.passwords.is_empty() {
                config.passwords[0].clone()
            } else {
                "".to_string()
            };

            results.push(GpuSearchResult {
                mnemonic,
                password,
                work_item_index,
            });
        }

        Ok(results)
    }
}

impl Drop for GpuSearcher {
    fn drop(&mut self) {
        info!("[GPU] 释放GPU资源");
    }
}
