#utility functions for sigCUDA package

"""
read a file and return its contents as a vector of bytes

# Arguments
-path::AbstractString: Path to the file to read

# Returns
-Vector{UInt8}: File contents as bytes

# Throws
-SystemError: If the file cannot be read
"""

function read_file_bytes(path::AbstractString)::Vector{UInt8}
    open(path, "r") do io
        return read(io)
    end
end

"""
convert a space-separated hexadecimal string to a vector of bytes

Arguments
-s::String: Space-separated hex string (e.g., "48 65 6C 6C 6F")

Returns
-Vector{UInt8}: Decoded bytes

Throws
-ArgumentError: If the hex string is invalid
"""

function hex_string_to_bytes(input_string::String)::Vector{UInt8}
    hex_parts = split(strip(input_string))
    bytes = Vector{UInt8}(undef, length(hex_parts))
    
    for (index, hex_part) in enumerate(hex_parts)
        if length(hex_part) != 2
            throw(ArgumentError("Invalid hex byte: '$hex_part' (must be 2 characters)"))
        end
        try
            bytes[index] = parse(UInt8, hex_part, base=16)
        catch error
            throw(ArgumentError("Invalid hex byte: '$hex_part' -$error"))
        end
    end
    
    return bytes
end

"""
convert a mask string to a vector of booleans

Arguments
-s::String: Mask string where 'F' means match required and '0' means wildcard

Returns
-Vector{Bool}: Boolean mask where true means match required, false means wildcard

Throws
-ArgumentError: If the mask string contains invalid characters
"""

function mask_string_to_bools(input_string::String)::Vector{Bool}
    mask = Vector{Bool}(undef, length(input_string))
    
    for (index, character) in enumerate(input_string)
        if character == 'F'
            mask[index] = true
        elseif character == '0'
            mask[index] = false
        else
            throw(ArgumentError("Invalid mask character: '$character' at position $index (must be 'F' or '0')"))
        end
    end
    
    return mask
end

"""
convert a string to a vector of bytes using UTF-8 encoding

Arguments
-s::String: String to convert

Returns
-Vector{UInt8}: UTF-8 encoded bytes
"""

function string_to_bytes(input_string::String)::Vector{UInt8}
    return Vector{UInt8}(input_string)
end


