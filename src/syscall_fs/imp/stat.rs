//! 获取文件系统状态信息
//!

use crate::{get_fs_stat, FsStat, SyscallError, SyscallResult};
use axfs::api::{FileIOType, Kstat, Statx};
use axlog::{debug, error, info};
use axprocess::{
    current_process,
    link::{deal_with_path, raw_ptr_to_ref_str, FilePath, AT_FDCWD},
};

use crate::syscall_fs::ctype::mount::get_stat_in_fs;

/// 实现 stat 系列系统调用
/// # Arguments
/// * `fd` - usize
/// * `kst` - *mut Kstat
pub fn syscall_fstat(args: [usize; 6]) -> SyscallResult {
    let fd = args[0];
    let kst = args[1] as *mut Kstat;
    let process = current_process();
    let fd_table = process.fd_manager.fd_table.lock();

    if fd >= fd_table.len() || fd < 3 {
        debug!("fd {} is out of range", fd);
        return Err(SyscallError::EPERM);
    }
    if fd_table[fd].is_none() {
        debug!("fd {} is none", fd);
        return Err(SyscallError::EPERM);
    }
    let file = fd_table[fd].clone().unwrap();
    if file.get_type() != FileIOType::FileDesc {
        debug!("fd {} is not a file", fd);
        return Err(SyscallError::EPERM);
    }

    match file.get_stat() {
        Ok(stat) => {
            unsafe {
                *kst = stat;
            }
            Ok(0)
        }
        Err(e) => {
            debug!("get stat error: {:?}", e);
            Err(SyscallError::EPERM)
        }
    }
}

/// 获取文件状态信息，但是给出的是目录 fd 和相对路径。
/// # Arguments
/// * `dir_fd` - usize
/// * `path` - *const u8
/// * `kst` - *mut Kstat
pub fn syscall_fstatat(args: [usize; 6]) -> SyscallResult {
    let dir_fd = args[0];
    let path = args[1] as *const u8;
    let kst = args[2] as *mut Kstat;
    let file_path = if let Some(file_path) = deal_with_path(dir_fd, Some(path), false) {
        // error!("test {:?}", file_path);
        file_path
    } else {
        // x86 下应用会调用 newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0xe), ...}, AT_EMPTY_PATH) = 0
        // 去尝试检查 STDOUT 的属性。这里暂时先特判，以后再改成真正的 stdout 的属性
        let path = unsafe { raw_ptr_to_ref_str(path) };
        if path.is_empty() && dir_fd == 1 {
            unsafe {
                (*kst).st_mode = 0o20000 | 0o220u32;
                (*kst).st_ino = 1;
                (*kst).st_nlink = 1;
            }
            return Ok(0);
        }
        panic!("Wrong path at syscall_fstatat: {}(dir_fd={})", path, dir_fd);
    };
    info!("path : {}", file_path.path());
    if !axfs::api::path_exists(file_path.path()) {
        return Err(SyscallError::ENOENT);
    }
    match get_stat_in_fs(&file_path) {
        Ok(stat) => unsafe {
            *kst = stat;
            Ok(0)
        },
        Err(error_no) => {
            debug!("get stat error: {:?}", error_no);
            Err(error_no)
        }
    }
}

/// 获取文件状态信息
/// # Arguments
/// * `path` - *const u8
/// * `kst` - *mut Kstat
#[cfg(target_arch = "x86_64")]
pub fn syscall_lstat(args: [usize; 6]) -> SyscallResult {
    let path = args[0];
    let kst = args[1];
    let temp_args = [AT_FDCWD, path, kst, 0, 0, 0];
    syscall_fstatat(temp_args)
}

/// 获取文件状态信息
/// # Arguments
/// * `path` - *const u8
/// * `stat_ptr` - *mut Kstat
#[cfg(target_arch = "x86_64")]
pub fn syscall_stat(args: [usize; 6]) -> SyscallResult {
    let path = args[0];
    let stat_ptr = args[1];
    let temp_args = [AT_FDCWD, path, stat_ptr, 0, 0, 0];
    syscall_fstatat(temp_args)
}

/// 获取文件系统的信息
/// # Arguments
/// * `path` - *const u8
/// * `stat` - *mut FsStat
pub fn syscall_statfs(args: [usize; 6]) -> SyscallResult {
    let path = args[0] as *const u8;
    let stat = args[1] as *mut FsStat;
    let file_path = deal_with_path(AT_FDCWD, Some(path), false).unwrap();
    if file_path.equal_to(&FilePath::new("/").unwrap()) {
        // 目前只支持访问根目录文件系统的信息
        unsafe {
            *stat = get_fs_stat();
        }

        Ok(0)
    } else {
        error!("Only support fs_stat for root");
        Err(SyscallError::EINVAL)
    }
}

/// 获取文件状态信息
/// # Arguments
/// * `dir_fd` - usize
/// * `path` - *const u8
/// * `flags` - usize
/// * `mask` - usize
/// * `stat_ptr` - *mut Xstat
#[cfg(target_arch = "x86_64")]
pub fn syscall_statx(args: [usize; 6]) -> SyscallResult {
    let dir_fd = args[0];
    let path = args[1];
    let _flags = args[2];
    let _mask = args[3];
    let kst = args[4] as *mut Statx;

    let temp = [dir_fd, path, kst as usize, 0, 0, 0];
    let res = syscall_fstatat(temp);
    unsafe { *kst = cp_statx(kst as *mut Kstat); }
    res
}

#[cfg(target_arch = "x86_64")]
fn cp_statx(obj: *mut Kstat) -> Statx {
    unsafe {
        Statx {
            stx_mask: 0x07ff,
            stx_blksize: (*obj).st_blksize,
            stx_attributes: 0,
            stx_nlink: (*obj).st_nlink as u32,
            stx_uid: (*obj).st_uid,
            stx_gid: (*obj).st_gid,
            stx_mode: (*obj).st_mode as u16,
            _pad0: [0; 1],
            stx_ino: (*obj).st_ino,
            stx_size: (*obj).st_size,
            stx_blocks: (*obj).st_blocks,
            stx_attributes_mask: 0,
            stx_atime_sec: (*obj).st_atime_sec,
            stx_atime_nsec: (*obj).st_atime_sec,
            stx_btime_sec: (*obj).st_mtime_sec,
            stx_btime_nsec: (*obj).st_mtime_sec,
            stx_ctime_sec: (*obj).st_ctime_sec,
            stx_ctime_nsec: (*obj).st_ctime_sec,
            stx_mtime_sec: (*obj).st_mtime_sec,
            stx_mtime_nsec: (*obj).st_mtime_nsec,
            stx_rdev: (*obj).st_rdev,
            stx_dev: (*obj).st_dev,
            ..Statx::default()
        }
    }
}