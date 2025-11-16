#sigCUDA: A signature matching module with CUDA acceleration

module sigCUDA

using CUDA
using JSON3

#include all submodules

include("utils.jl")
include("signatures.jl")
include("cpu_matcher.jl")
include("gpu_matcher.jl")
include("api.jl")

#export public API

export
    #types
    Signature,
    SignatureDB,
    ScanConfig,
    GPUSignatureDB,
    
    #database loading
    load_db,
    load_signature_db,
    
    #CPU matchers
    scan_buffer_cpu,
    scan_buffers_cpu,
    
    #GPU matchers
    scan_buffer_gpu,
    scan_buffers_gpu,
    has_gpu,
    to_gpu,
    
    #high-level API
    scan_buffer,
    scan_file,
    scan_directory,
    default_scan_config,
    
    #utilities
    read_file_bytes,
    hex_string_to_bytes,
    mask_string_to_bools,
    string_to_bytes,
    print_match

end

