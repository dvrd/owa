# Odin imports

Omit the alias when it repeats the last component of the import path. Write `import "core:encoding/endian"` and `import "shared:surf"`. Use an explicit alias when the code needs a different local name.

# Odin block spacing

Leave a blank line between the closing `}` of a completed brace-delimited construct and the next statement or declaration. This applies to structs, procedures, control-flow statements, and braced literals, including single-line forms.

The only exception is an `if` immediately followed by a `defer` that frees memory. Keep those lines together:

```odin
data, err := os.read_entire_file(path, context.allocator)
if err != nil {
	return err
}
defer delete(data)

process(data)
```

Leave a blank line after every complete `defer` statement, including between consecutive defers and before a closing brace. For a deferred block, place the blank line after its closing brace.
