//! OpenCL上下文管理 - 参考rust-profanity实现

use log::info;
use ocl::{Context, Device, Platform, Queue};

/// OpenCL上下文
pub struct OpenCLContext {
    pub platform: Platform,
    pub device: Device,
    pub context: Context,
    pub queue: Queue,
}

impl OpenCLContext {
    /// 创建新的OpenCL上下文，自动选择GPU设备
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let platforms = Platform::list();
        if platforms.is_empty() {
            return Err("未找到OpenCL平台".into());
        }

        info!("[OpenCL] 找到 {} 个平台", platforms.len());

        // 选择第一个GPU设备
        let mut selected_platform = None;
        let mut selected_device = None;

        for platform in &platforms {
            let devices = Device::list_all(platform)?;
            info!(
                "[OpenCL] 平台: {:?}, 设备数: {}",
                platform.name(),
                devices.len()
            );

            for device in devices {
                let device_name = device.name()?;
                let device_type = Self::get_device_type(&device);
                info!("[OpenCL]   设备: {} (类型: {})", device_name, device_type);

                if device_type == "GPU" {
                    selected_platform = Some(*platform);
                    selected_device = Some(device);
                    break;
                }
            }

            if selected_device.is_some() {
                break;
            }
        }

        let (platform, device) = if let (Some(p), Some(d)) = (selected_platform, selected_device) {
            info!("[OpenCL] 选择GPU设备");
            (p, d)
        } else {
            info!("[OpenCL] 未找到GPU，使用第一个设备");
            let p = platforms[0];
            let devices = Device::list_all(p)?;
            if devices.is_empty() {
                return Err("未找到OpenCL设备".into());
            }
            (p, devices[0])
        };

        let device_name = device.name()?;
        info!("[OpenCL] 使用设备: {}", device_name);

        // 创建上下文
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()?;

        // 创建命令队列
        let queue = Queue::new(&context, device, None)?;

        Ok(Self {
            platform,
            device,
            context,
            queue,
        })
    }

    /// 获取设备类型
    fn get_device_type(device: &Device) -> String {
        let device_name = device.name().unwrap_or_default();
        let name_lower = device_name.to_lowercase();

        if name_lower.contains("gpu")
            || name_lower.contains("graphics")
            || name_lower.contains("nvidia")
            || name_lower.contains("amd")
            || name_lower.contains("radeon")
        {
            "GPU".to_string()
        } else if name_lower.contains("cpu") {
            "CPU".to_string()
        } else {
            "UNKNOWN".to_string()
        }
    }

    /// 打印设备信息
    pub fn print_device_info(&self) -> Result<(), Box<dyn std::error::Error>> {
        let name = self.device.name()?;
        let vendor = self.device.vendor()?;
        let version = self.device.version()?;

        info!("[OpenCL] 设备信息:");
        info!("[OpenCL]   名称: {}", name);
        info!("[OpenCL]   厂商: {}", vendor);
        info!("[OpenCL]   版本: {}", version);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试 OpenCL 上下文创建。
    ///
    /// 需要启用 `gpu-tests` feature 才会运行（需要真实的 OpenCL 设备）。
    /// 用法: `cargo test --features gpu-tests`
    #[test]
    #[cfg_attr(
        not(feature = "gpu-tests"),
        ignore = "需要 GPU 设备: cargo test --features gpu-tests"
    )]
    fn test_context_creation() {
        let ctx = OpenCLContext::new();
        assert!(ctx.is_ok());
    }
}
