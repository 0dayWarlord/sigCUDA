#GPU-based signature matching implementation using CUDA

using CUDA

"""
GPU representation of a signature database

Fields
-patterns::CuArray{UInt8,1}: Flattened array of all pattern bytes
-masks::CuArray{Bool,1}: Flattened array of all mask booleans
-sig_offsets::CuArray{Int32,1}: Starting index in patterns/masks for each signature
-sig_lengths::CuArray{Int32,1}: Length of each signature pattern
-ids::Vector{String}: Signature IDs (kept on CPU for reporting)
-severities::CuArray{Int32,1}: Severity levels for each signature
-cpu_db::SignatureDB: Reference to original CPU database for mapping results
"""

struct GPUSignatureDB
    patterns::CuArray{UInt8}
    masks::CuArray{Bool}
    sig_offsets::CuArray{Int32}  # Legacy field name, maps to signature_offsets
    sig_lengths::CuArray{Int32}  # Legacy field name, maps to signature_lengths
    ids::Vector{String}
    severities::CuArray{Int32}
    cpu_db::SignatureDB
end

"""
check if a CUDA-capable GPU is available

Returns
-Bool: true if CUDA is available, false otherwise
"""

function has_gpu()::Bool
    return CUDA.has_cuda()
end

"""
convert a CPU SignatureDB to GPU representation

Arguments
-db::SignatureDB: CPU signature database

Returns
-GPUSignatureDB: GPU representation of the database

Throws
-ErrorException: If CUDA is not available
"""

function to_gpu(database::SignatureDB)::GPUSignatureDB
    if !has_gpu()
        throw(ErrorException("CUDA is not available. Cannot convert SignatureDB to GPU representation."))
    end
    
    number_of_signatures = length(database.signatures)
    
    #calculate total size needed
    total_pattern_bytes = sum(length(signature.pattern) for signature in database.signatures)
    
    #build arrays on CPU first
    patterns_cpu = Vector{UInt8}(undef, total_pattern_bytes)
    masks_cpu = Vector{Bool}(undef, total_pattern_bytes)
    signature_offsets_cpu = Vector{Int32}(undef, number_of_signatures)
    signature_lengths_cpu = Vector{Int32}(undef, number_of_signatures)
    severities_cpu = Vector{Int32}(undef, number_of_signatures)
    ids = Vector{String}(undef, number_of_signatures)
    
    #fill arrays on CPU
    offset = 0
    for (index, signature) in enumerate(database.signatures)
        signature_offsets_cpu[index] = Int32(offset)
        signature_lengths_cpu[index] = Int32(length(signature.pattern))
        severities_cpu[index] = Int32(signature.severity)
        ids[index] = signature.id
        
        #copy pattern and mask
        patterns_cpu[(offset+1):(offset+length(signature.pattern))] = signature.pattern
        masks_cpu[(offset+1):(offset+length(signature.pattern))] = signature.mask
        
        offset += length(signature.pattern)
    end
    
    #transfer to GPU
    patterns = CuArray(patterns_cpu)
    masks = CuArray(masks_cpu)
    sig_offsets = CuArray(signature_offsets_cpu)
    sig_lengths = CuArray(signature_lengths_cpu)
    severities = CuArray(severities_cpu)
    
    return GPUSignatureDB(patterns, masks, sig_offsets, sig_lengths, ids, severities, database)
end

"""
CUDA kernel to scan data buffer for signature matches

Each thread checks one candidate starting position for all signatures
"""

function kernel_scan!(
    data::CuDeviceVector{UInt8},
    patterns::CuDeviceVector{UInt8},
    masks::CuDeviceVector{Bool},
    signature_offsets::CuDeviceVector{Int32},
    signature_lengths::CuDeviceVector{Int32},
    number_of_signatures::Int32,
    match_count::CuDeviceVector{Int32},
    matches_signature_index::CuDeviceVector{Int32},
    matches_position::CuDeviceVector{Int32},
    max_matches::Int32
)
    thread_index = threadIdx().x + (blockIdx().x -1) * blockDim().x
    data_length = length(data)
    
    #each thread processes one candidate starting position
    if thread_index <= data_length
        position = thread_index -1  #zero-based position
        
        #check each signature
        for signature_index in 1:number_of_signatures
            signature_offset = signature_offsets[signature_index]
            signature_length = signature_lengths[signature_index]
            
            #check if we have enough data remaining
            if position + signature_length > data_length
                continue
            end
            
            #check if this signature matches at this position
            matched = true
            for index in 1:signature_length
                pattern_index = signature_offset + index
                if masks[pattern_index]  # only check if mask requires match
                    #position is 0-based, data is 1-based, so use position + index
                    if data[position + index] != patterns[pattern_index]
                        matched = false
                        break
                    end
                end
            end
            
            #if matched, record it

            if matched
                #atomically increment match counter and get previous value (index to use)
                match_index = CUDA.atomic_add!(pointer(match_count), Int32(1))
                if match_index < max_matches
                    matches_signature_index[match_index + Int32(1)] = Int32(signature_index)
                    matches_position[match_index + Int32(1)] = Int32(position)
                end
            end
        end
    end
    
    return nothing
end

"""
scan a buffer for signature matches using GPU

Arguments
-db::SignatureDB: Signature database to match against
-data::Vector{UInt8}: Buffer to scan

Returns
-Vector{Tuple{Signature, Int}}: List of matches as (signature, offset) tuples

Throws
-ErrorException: If CUDA is not available
"""

function scan_buffer_gpu(database::SignatureDB, data::Vector{UInt8})::Vector{Tuple{Signature, Int}}
    if !has_gpu()
        throw(ErrorException("CUDA is not available. Use scan_buffer_cpu instead."))
    end
    
    if isempty(data)
        return Vector{Tuple{Signature, Int}}()
    end
    
    #convert database to GPU representation
    gpu_database = to_gpu(database)
    
    #transfer data to GPU
    data_gpu = CuArray(data)
    
    #allocate match storage (pessimistic: assume up to 1% of positions could match)
    max_matches = max(1024, div(length(data), 100))
    match_count = CuArray{Int32}([0])
    matches_signature_index = CuArray{Int32}(undef, max_matches)
    matches_position = CuArray{Int32}(undef, max_matches)
    
    #launch kernel
    threads_per_block = 256
    number_of_blocks = cld(length(data), threads_per_block)
    
    @cuda threads=threads_per_block blocks=number_of_blocks kernel_scan!(
        data_gpu,
        gpu_database.patterns,
        gpu_database.masks,
        gpu_database.sig_offsets,
        gpu_database.sig_lengths,
        Int32(length(database.signatures)),
        match_count,
        matches_signature_index,
        matches_position,
        Int32(max_matches)
    )
    
    #synchronize and copy results back
    CUDA.synchronize()
    
    number_of_matches = Int(Array(match_count)[1])
    if number_of_matches > max_matches
        @warn "Match buffer overflow: found $number_of_matches matches but only allocated $max_matches. Results truncated."
        number_of_matches = max_matches
    end
    
    #build result list
    matches = Vector{Tuple{Signature, Int}}()
    if number_of_matches > 0
        signature_indices = Array(matches_signature_index[1:number_of_matches])
        positions = Array(matches_position[1:number_of_matches])
        
        for index in 1:number_of_matches
            signature_index = Int(signature_indices[index])
            position = Int(positions[index])
            signature = database.signatures[signature_index]
            push!(matches, (signature, position))
        end
    end
    
    return matches
end

"""
scan multiple buffers for signature matches using GPU

Currently processes buffers sequentially. Future optimization could batch them

Arguments
-db::SignatureDB: Signature database to match against
-buffers::Vector{Vector{UInt8}}: List of buffers to scan

Returns
-Vector{Vector{Tuple{Signature, Int}}}: List of match lists, one per buffer

Throws
-ErrorException: If CUDA is not available
"""

function scan_buffers_gpu(database::SignatureDB, buffers::Vector{Vector{UInt8}})::Vector{Vector{Tuple{Signature, Int}}}
    if !has_gpu()
        throw(ErrorException("CUDA is not available. Use scan_buffers_cpu instead."))
    end
    
    return [scan_buffer_gpu(database, buffer) for buffer in buffers]
end

