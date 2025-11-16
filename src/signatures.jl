#signature data structures and parsing for sigCUDA

using JSON3

"""
represents a single signature pattern with optional wildcards

# Fields
-id::String: Unique identifier for the signature
-pattern::Vector{UInt8}: The raw byte pattern
-mask::Vector{Bool}: Boolean mask where true means byte must match, false means wildcard
-severity::Int: Severity level (1-10)
-description::String: Human-readable description
"""

struct Signature
    id::String
    pattern::Vector{UInt8}
    mask::Vector{Bool}
    severity::Int
    description::String
    
    function Signature(id::String, pattern::Vector{UInt8}, mask::Vector{Bool}, severity::Int, description::String)
        if length(pattern) != length(mask)
            throw(ArgumentError("Pattern and mask must have the same length (pattern: $(length(pattern)), mask: $(length(mask)))"))
        end
        if isempty(pattern)
            throw(ArgumentError("Pattern cannot be empty"))
        end
        if severity < 1 || severity > 10
            throw(ArgumentError("Severity must be between 1 and 10 (got $severity)"))
        end
        new(id, pattern, mask, severity, description)
    end
end

"""
container for a collection of signatures

Fields
-signatures::Vector{Signature}: List of signatures
"""

struct SignatureDB
    signatures::Vector{Signature}
    
    function SignatureDB(signatures::Vector{Signature})
        if isempty(signatures)
            throw(ArgumentError("SignatureDB cannot be empty"))
        end
        new(signatures)
    end
end

"""
parse a hexadecimal pattern string and mask string into bytes and boolean mask

Arguments
-pattern_hex::String: Space-separated hexadecimal string
-mask::String: Mask string with 'F' for match and '0' for wildcard

Returns
-Tuple{Vector{UInt8}, Vector{Bool}}: Pattern bytes and boolean mask

Throws
-ArgumentError: If pattern_hex and mask lengths don't match or parsing fails
"""

function parse_pattern(pattern_hex::String, mask::String)::Tuple{Vector{UInt8}, Vector{Bool}}
    pattern = hex_string_to_bytes(pattern_hex)
    bool_mask = mask_string_to_bools(mask)
    
    if length(pattern) != length(bool_mask)
        throw(ArgumentError("Pattern and mask must have the same length (pattern: $(length(pattern)), mask: $(length(bool_mask)))"))
    end
    
    return (pattern, bool_mask)
end

"""
load a signature database from a JSON file

Arguments
-path::AbstractString: Path to the JSON signature file

Returns
-SignatureDB: Loaded signature database

Throws
-SystemError: If the file cannot be read
-ArgumentError: If the JSON is invalid or signatures are malformed

JSON Format
The JSON file should contain an array of signature objects:
```json
[
  {
    "id": "THE_FUNKY_VIRUS",
    "pattern_hex": "48 65 6C 6C 6F",
    "mask": "FFFFF",
    "severity": 3,
    "description": "Oooooo ya get funky ya ya"
  }
]
```
"""

function load_signature_db(path::AbstractString)::SignatureDB
    json_data = JSON3.read(read(path, String))
    
    if !(json_data isa AbstractVector)
        throw(ArgumentError("JSON file must contain an array of signatures"))
    end
    
    signatures = Vector{Signature}()
    
    for (index, signature_object) in enumerate(json_data)
        try
            id = String(signature_object.id)
            pattern_hex = String(signature_object.pattern_hex)
            mask_string = String(signature_object.mask)
            severity = Int(signature_object.severity)
            description = String(signature_object.description)
            
            pattern, mask = parse_pattern(pattern_hex, mask_string)
            signature = Signature(id, pattern, mask, severity, description)
            push!(signatures, signature)
        catch error
            throw(ArgumentError("Error parsing signature at index $index: $error"))
        end
    end
    
    if isempty(signatures)
        throw(ArgumentError("No valid signatures found in file"))
    end
    
    return SignatureDB(signatures)
end

"""
print a signature match

# Arguments
-sig::Signature: The matched signature
-offset::Int: The byte offset where the match occurred
"""

function print_match(signature::Signature, offset::Int)
    println("Match: $(signature.id) at offset $offset (severity=$(signature.severity))")
    println("  Description: $(signature.description)")
end

