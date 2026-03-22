/// Converts a CPU mask string into a sorted vector of CPU indices.
pub fn parse_cpumask(input: &str) -> Result<Vec<u32>, String> {
    let mut cpumask = Vec::new();
    let max_cpu = libbpf_rs::num_possible_cpus().unwrap();

    // Split the string by commas to handle multiple ranges
    for range in input.split(',') {
        // Split the range by hyphen
        let bounds: Vec<&str> = range.split('-').collect();

        match bounds.as_slice() {
            // Single number, e.g., "4"
            [single] => {
                let num: u32 = single
                    .parse()
                    .map_err(|_| format!("Invalid number: {}", single))?;
                if num >= max_cpu as u32 {
                    return Err(format!("CPU {} exceeds max CPU {}", num, max_cpu - 1));
                }
                cpumask.push(num);
            }
            // Range, e.g., "2-5"
            [start, end] => {
                let start: u32 = start
                    .parse()
                    .map_err(|_| format!("Invalid start of range: {}", start))?;
                let end: u32 = end
                    .parse()
                    .map_err(|_| format!("Invalid end of range: {}", end))?;

                if start > end {
                    return Err(format!("Invalid range: {}-{}", start, end));
                }

                if end >= max_cpu as u32 {
                    return Err(format!("CPU {} exceeds max CPU {}", end, max_cpu - 1));
                }
                for cpu in start..=end {
                    cpumask.push(cpu);
                }
            }
            // Invalid format
            _ => return Err(format!("Invalid range format: {}", range)),
        }
    }

    // Sort and deduplicate the results
    cpumask.sort_unstable();
    cpumask.dedup();

    Ok(cpumask)
}
