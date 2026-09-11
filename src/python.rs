use std::path::PathBuf;
use std::time::Duration;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyKeyboardInterrupt};
use pyo3::prelude::*;

use crate::{CancellationToken, ExtractOptions, is_cancellation};

create_exception!(otadump, OtaDumpError, PyException);

#[pyclass(name = "CancellationToken")]
struct PyCancellationToken {
    token: CancellationToken,
}

#[pymethods]
impl PyCancellationToken {
    #[new]
    fn new() -> Self {
        Self { token: CancellationToken::new() }
    }

    fn cancel(&self) {
        self.token.cancel();
    }

    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

/// Extract partitions from an Android OTA payload or OTA ZIP.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    payload_file,
    output_dir,
    *,
    num_threads = None,
    overwrite = false,
    partitions = None,
    verify = true,
    source_dir = None,
    cancellation_token = None,
))]
fn extract(
    py: Python<'_>,
    payload_file: PathBuf,
    output_dir: PathBuf,
    num_threads: Option<usize>,
    overwrite: bool,
    partitions: Option<Vec<String>>,
    verify: bool,
    source_dir: Option<PathBuf>,
    cancellation_token: Option<PyRef<'_, PyCancellationToken>>,
) -> PyResult<()> {
    let cancellation_token =
        cancellation_token.map(|token| token.token.clone()).unwrap_or_default();
    let mut options = ExtractOptions::new();
    options.overwrite(overwrite).verify(verify).cancellation_token(&cancellation_token);

    if let Some(num_threads) = num_threads {
        options.num_threads(num_threads);
    }
    if let Some(partitions) = partitions {
        options.partitions(partitions);
    }
    if let Some(source_dir) = source_dir {
        options.source_dir(source_dir);
    }

    let extraction = std::thread::spawn(move || match options.extract(payload_file, output_dir) {
        Ok(()) => Ok(()),
        Err(error) if is_cancellation(error.as_ref()) => Err(None),
        Err(error) => Err(Some(error.to_string())),
    });

    let mut signal_error = None;
    while !extraction.is_finished() {
        if signal_error.is_none() {
            if let Err(error) = py.check_signals() {
                cancellation_token.cancel();
                signal_error = Some(error);
            }
        }
        py.detach(|| std::thread::sleep(Duration::from_millis(20)));
    }
    let result =
        extraction.join().map_err(|_| OtaDumpError::new_err("Extraction worker panicked"))?;
    if let Some(error) = signal_error {
        return Err(error);
    }
    match result {
        Ok(()) => Ok(()),
        Err(None) => Err(PyKeyboardInterrupt::new_err("Extraction cancelled")),
        Err(Some(error)) => Err(OtaDumpError::new_err(error)),
    }
}

#[pymodule]
fn otadump(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("OtaDumpError", module.py().get_type::<OtaDumpError>())?;
    module.add_class::<PyCancellationToken>()?;
    module.add_function(wrap_pyfunction!(extract, module)?)?;
    Ok(())
}
