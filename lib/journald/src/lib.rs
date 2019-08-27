#[macro_use]
extern crate dlopen_derive;

use dlopen::wrapper::{Container, WrapperApi};
use libc::size_t;
use std::collections::HashMap;
use std::io::{Error as IOError, Result as IOResult};
use std::iter;
use std::os::raw::c_int;
use std::ptr::null_mut;

pub const SD_JOURNAL_LOCAL_ONLY: c_int = 1;
pub const SD_JOURNAL_RUNTIME_ONLY: c_int = 2;
pub const SD_JOURNAL_SYSTEM: c_int = 4;
pub const SD_JOURNAL_CURRENT_USER: c_int = 8;

#[allow(non_camel_case_types)]
pub enum sd_journal {}

#[derive(WrapperApi)]
struct LibSystemd {
    sd_journal_open: extern "C" fn(ret: *mut *mut sd_journal, flags: c_int) -> c_int,
    sd_journal_close: extern "C" fn(j: *mut sd_journal),
    sd_journal_next: extern "C" fn(j: *mut sd_journal) -> c_int,
    sd_journal_seek_head: extern "C" fn(j: *mut sd_journal) -> c_int,
    sd_journal_restart_data: extern "C" fn(j: *mut sd_journal),
    sd_journal_enumerate_data:
        extern "C" fn(j: *mut sd_journal, data: *const *mut u8, l: *mut size_t) -> c_int,
}

fn load_lib() -> Result<Container<LibSystemd>, dlopen::Error> {
    unsafe { Container::load("libsystemd.so") }
}

pub struct Journal {
    lib: Container<LibSystemd>,
    journal: *mut sd_journal,
}

unsafe impl Send for Journal {}

pub type Record = HashMap<String, String>;

impl Journal {
    pub fn open(flags: c_int) -> IOResult<Journal> {
        // Each Journal structure gets their own handle to the library,
        // but I couldn't figure out how to make lazy_static work.
        let lib = load_lib().map_err(|err| IOError::new(std::io::ErrorKind::Other, err))?;

        let mut journal = null_mut();
        sd_result(lib.sd_journal_open(&mut journal, flags))?;
        sd_result(lib.sd_journal_seek_head(journal))?;
        Ok(Journal { lib, journal })
    }

    pub fn get_record(&mut self) -> IOResult<Record> {
        self.lib.sd_journal_restart_data(self.journal);

        iter::from_fn(|| {
            let mut size: size_t = 0;
            let data: *mut u8 = null_mut();

            match sd_result(
                self.lib
                    .sd_journal_enumerate_data(self.journal, &data, &mut size),
            ) {
                Err(err) => Some(Err(err)),
                Ok(0) => None,

                Ok(_) => {
                    let b = unsafe { std::slice::from_raw_parts(data, size as usize) };
                    let field = String::from_utf8_lossy(b);
                    let eq = field.find('=').unwrap();
                    Some(Ok((field[..eq].into(), field[eq + 1..].into())))
                }
            }
        })
        .collect::<IOResult<Record>>()
    }
}

impl Iterator for Journal {
    type Item = IOResult<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        match sd_result(self.lib.sd_journal_next(self.journal)) {
            Err(err) => Some(Err(err)),
            Ok(0) => None,
            _ => Some(self.get_record()),
        }
    }
}

fn sd_result(code: c_int) -> IOResult<c_int> {
    match code {
        _ if code < 0 => Err(IOError::from_raw_os_error(-code)),
        _ => Ok(code),
    }
}
