#CPU-based signature matching implementation


"""
scan a buffer for signature matches using CPU

Arguments
-db::SignatureDB: Signature database to match against
-data::Vector{UInt8}: Buffer to scan

Returns
-Vector{Tuple{Signature, Int}}: List of matches as (signature, offset) tuples, where offset is zero-based
"""

function scan_buffer_cpu(database::SignatureDB, data::Vector{UInt8})::Vector{Tuple{Signature, Int}}
    matches = Vector{Tuple{Signature, Int}}()
    
    if isempty(data)
        return matches
    end
    
    for signature in database.signatures
        pattern_length = length(signature.pattern)
        
        #early abort if buffer is shorter than pattern
        if length(data) < pattern_length
            continue
        end
        
        #try each possible starting position
        for offset in 0:(length(data) -pattern_length)
            matched = true
            
            #check each byte in the pattern
            for index in 1:pattern_length
                #only check bytes where mask is true (not wildcard)
                if signature.mask[index]
                    if data[offset + index] != signature.pattern[index]
                        matched = false
                        break
                    end
                end
            end
            
            if matched
                push!(matches, (signature, offset))
            end
        end
    end
    
    return matches
end

"""
scan multiple buffers for signature matches using CPU

Arguments
-db::SignatureDB: Signature database to match against
-buffers::Vector{Vector{UInt8}}: List of buffers to scan

Returns
-Vector{Vector{Tuple{Signature, Int}}}: List of match lists, one per buffer
"""

function scan_buffers_cpu(database::SignatureDB, buffers::Vector{Vector{UInt8}})::Vector{Vector{Tuple{Signature, Int}}}
    return [scan_buffer_cpu(database, buffer) for buffer in buffers]
end