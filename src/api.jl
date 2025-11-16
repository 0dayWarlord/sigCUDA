#high-level API for sigCUDA

"""
configuration for scanning operations

# Fields
-use_gpu::Bool: Whether to use GPU acceleration when available
-min_gpu_bytes::Int: Minimum buffer size (in bytes) before GPU is used
"""

struct ScanConfig
    use_gpu::Bool
    min_gpu_bytes::Int
    
    function ScanConfig(use_gpu::Bool = true, min_gpu_bytes::Int = 1_000_000)
        if min_gpu_bytes < 0
            throw(ArgumentError("min_gpu_bytes must be non-negative"))
        end
        new(use_gpu, min_gpu_bytes)
    end
end

"""
get the default scan configuration

Returns
-ScanConfig: Default configuration with GPU enabled and 1MB minimum size
"""

function default_scan_config()::ScanConfig
    return ScanConfig(true, 1_000_000)
end

"""
load a signature database from a JSON file

Arguments
-path::AbstractString: Path to the JSON signature file

Returns
-SignatureDB: Loaded signature database
"""
function load_db(path::AbstractString)::SignatureDB
    return load_signature_db(path)
end

"""
scan a buffer for signature matches, automatically choosing CPU or GPU based on configuration

Arguments
-db::SignatureDB: Signature database to match against
-data::Vector{UInt8}: Buffer to scan
-config::ScanConfig: Configuration for scanning (default: use GPU if available and buffer >= 1MB)

Returns
-Vector{Tuple{Signature, Int}}: List of matches as (signature, offset) tuples
"""

function scan_buffer(
    database::SignatureDB,
    data::Vector{UInt8};
    config::ScanConfig = default_scan_config()
)::Vector{Tuple{Signature, Int}}
    use_gpu = config.use_gpu && has_gpu() && length(data) >= config.min_gpu_bytes
    
    if use_gpu
        return scan_buffer_gpu(database, data)
    else
        return scan_buffer_cpu(database, data)
    end
end

"""
scan a file for signature matches

Arguments
-db::SignatureDB: Signature database to match against
-path::AbstractString: Path to the file to scan
-config::ScanConfig: Configuration for scanning

Returns
-Vector{Tuple{Signature, Int}}: List of matches as (signature, offset) tuples

Throws
-SystemError: If the file cannot be read
"""

function scan_file(
    database::SignatureDB,
    path::AbstractString;
    config::ScanConfig = default_scan_config()
)::Vector{Tuple{Signature, Int}}
    data = read_file_bytes(path)
    return scan_buffer(database, data; config = config)
end

"""
scan all files in a directory for signature matches

Arguments
-db::SignatureDB: Signature database to match against
-path::AbstractString: Path to the directory to scan
-recursive::Bool: Whether to scan subdirectories recursively (default: true)
-config::ScanConfig: Configuration for scanning

Returns
-Dict{String, Vector{Tuple{Signature, Int}}}: Dictionary mapping file paths to their matches

Throws
-SystemError: If the directory cannot be read
"""

function scan_directory(
    database::SignatureDB,
    path::AbstractString;
    recursive::Bool = true,
    config::ScanConfig = default_scan_config()
)::Dict{String, Vector{Tuple{Signature, Int}}}
    results = Dict{String, Vector{Tuple{Signature, Int}}}()
    
    function scan_file_in_dir(file_path::String)
        try
            matches = scan_file(database, file_path; config = config)
            if !isempty(matches)
                results[file_path] = matches
            end
        catch error
            #skip files that can't be read (permissions, etc.)
            @warn "Failed to scan $file_path: $error"
        end
    end
    
    if recursive
        for (root, dirs, files) in walkdir(path)
            for file in files
                file_path = joinpath(root, file)
                scan_file_in_dir(file_path)
            end
        end
    else
        for entry in readdir(path; join = true)
            if isfile(entry)
                scan_file_in_dir(entry)
            end
        end
    end
    
    return results
end

