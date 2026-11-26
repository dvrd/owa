#+feature dynamic-literals
package main

import "core:fmt"
import "core:os"
import "core:strings"

join :: proc(a, b: string) -> string {
	path, err := os.join_path({a, b}, context.allocator)
	assert(err == nil)
	return path
}

env_or :: proc(name, fallback: string) -> string {
	value := os.get_env(name, context.allocator)
	return fallback if value == "" else value
}

// Plain source snapshots omit hidden files. Git checkouts use the index and
// unignored working files, including changes that haven't been committed.
list_files :: proc(root: string, paths: ^[dynamic]string, prefix := "", sdk := false) -> os.Error {
	entries := os.read_directory_by_path(join(root, prefix), -1, context.allocator) or_return
	for entry in entries {
		if strings.has_prefix(entry.name, ".") || entry.name == "__pycache__" {
			continue
		}

		path := join(prefix, entry.name)
		#partial switch entry.type {
		case .Directory:
			if sdk && entry.name == "tests" {
				continue
			}

			list_files(root, paths, path, sdk) or_return
		case .Regular:
			if !sdk ||
			   (strings.has_suffix(path, ".odin") && !strings.has_suffix(path, "_test.odin")) {
				append(paths, path)
			}


		case:
		}
	}

	return nil
}

stage_tree :: proc(root, dest: string) -> os.Error {
	files: [dynamic]string
	if os.exists(join(root, ".git")) {
		names := capture(
			{"git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"},
		) or_return
		for name in strings.split_iterator(&names, "\x00") {
			if name != "" {
				append(&files, name)
			}
		}
	} else {
		list_files(root, &files) or_return
	}

	os.make_directory_all(dest) or_return
	for path in files {
		src := join(root, path)
		info, err := os.lstat(src, context.allocator)
		if err == .Not_Exist {
			continue
		}

		if err != nil {
			return err
		}

		if info.type != .Regular && info.type != .Symlink {
			continue
		}

		target := join(dest, path)
		if mkdir_err := os.make_directory_all(os.dir(target));
		   mkdir_err != nil && mkdir_err != .Exist {
			return mkdir_err
		}

		if info.type == .Symlink {
			link := os.read_link(src, context.allocator) or_return
			os.symlink(link, target) or_return
		} else {
			os.copy_file(target, src) or_return
			os.chmod(target, info.mode) or_return
		}
	}

	return nil
}

// Read literal imports from each package, including SDK imports and older
// dependencies that reach sibling packages with relative paths.
scan_imports :: proc(
	root, boundary, shared: string,
	pending: ^[dynamic]string,
	sdk := false,
) -> os.Error {
	paths: [dynamic]string
	list_files(root, &paths, "", sdk) or_return
	for path in paths {
		if !strings.has_suffix(path, ".odin") {
			continue
		}

		file := join(root, path)
		data := os.read_entire_file(file, context.allocator) or_return
		defer delete(data)

		lines := string(data)
		for raw_line in strings.split_lines_iterator(&lines) {
			line := strings.trim_prefix(strings.trim_space(raw_line), "using ")
			if !strings.has_prefix(line, "import ") && !strings.has_prefix(line, "import\t") {
				continue
			}

			i := strings.index(line, "\"")
			if i < 0 {
				continue
			}

			value := line[i + 1:]
			end := strings.index(value, "\"")
			if end < 0 {
				continue
			}

			value = value[:end]
			if strings.has_prefix(value, "shared:") {
				name := value[len("shared:"):]
				part, _ := strings.split_iterator(&name, "/")
				append(pending, strings.clone(part))
			} else if boundary != "" &&
			   (strings.has_prefix(value, "../") || strings.has_prefix(value, "./")) {
				target := join(os.dir(file), value)
				if target == boundary || strings.has_prefix(target, fmt.aprintf("%s/", boundary)) {
					continue
				}

				if shared == "" || !strings.has_prefix(target, fmt.aprintf("%s/", shared)) {
					fmt.eprintln("Relative import outside package collection:", file, value)
					return .Invalid_Path
				}

				name := target[len(shared) + 1:]
				part, _ := strings.split_iterator(&name, "/")
				append(pending, part)
			}
		}
	}

	return nil
}

stage :: proc(root, work, compiler, source: string) -> os.Error {
	repo := join(work, "repository")
	shared := join(work, "shared")
	stage_tree(root, repo) or_return
	os.make_directory(shared) or_return
	os.symlink(join(repo, "src"), join(shared, "whatsapp")) or_return
	pending: [dynamic]string
	scan_imports(join(repo, "src"), join(repo, "src"), "", &pending) or_return
	scan_imports(join(repo, "tests"), repo, "", &pending) or_return
	scan_imports(join(repo, "tools"), "", "", &pending) or_return
	sdk := capture({compiler, "root"}) or_return
	for dir in ([]string{"core", "vendor"}) {
		scan_imports(join(strings.trim_space(sdk), dir), "", "", &pending, true) or_return
	}

	seen := map[string]bool {
		"whatsapp" = true,
	}

	for i := 0; i < len(pending); i += 1 {
		name := pending[i]
		if seen[name] {
			continue
		}

		seen[name] = true
		dest := join(shared, name)
		if !os.is_dir(join(source, name)) {
			fmt.eprintln("Missing shared dependency:", name, "in", source)
			return .Not_Exist
		}

		stage_tree(join(source, name), dest) or_return
		scan_imports(dest, dest, shared, &pending) or_return
	}

	return nil
}
