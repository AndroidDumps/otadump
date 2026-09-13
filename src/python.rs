use std::path::PathBuf;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

use crate::ExtractOptions;

create_exception!(otadump, OtaDumpError, PyException);

/// Extract partitions from an Android OTA payload or OTA ZIP.
#[pyfunction]
#[pyo3(signature = (
    payload_file,
    output_dir,
    *,
    num_threads = None,
    overwrite = false,
    partitions = None,
    verify = true,
))]
fn extract(
    py: Python<'_>,
    payload_file: PathBuf,
    output_dir: PathBuf,
    num_threads: Option<usize>,
    overwrite: bool,
    partitions: Option<Vec<String>>,
    verify: bool,
) -> PyResult<()> {
    let mut options = ExtractOptions::new();
    options.overwrite(overwrite).verify(verify);

    if let Some(num_threads) = num_threads {
        options.num_threads(num_threads);
    }
    if let Some(partitions) = partitions {
        options.partitions(partitions);
    }

    py.detach(move || {
        options
            .extract(payload_file, output_dir)
            .map_err(|error| OtaDumpError::new_err(error.to_string()))
    })
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("OtaDumpError", module.py().get_type::<OtaDumpError>())?;
    module.add_function(wrap_pyfunction!(extract, module)?)?;
    Ok(())
}
