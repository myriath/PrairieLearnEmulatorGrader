#! /usr/bin/python3

import json
import os
import pathlib
import re
import shlex
import subprocess
import random

CODEBASE = "/grade/student"
DATAFILE = "/grade/data/data.json"
SB_USER = "sbuser"

# List of symbols that are not allowed to be used in student code
INVALID_SYMBOLS = frozenset(
    (
        "__asan_default_options",
        "__asan_on_error",
        "__asan_malloc_hook",
        "__asan_free_hook",
        "__asan_unpoison_memory_region",
        "__asan_set_error_exit_code",
        "__asan_set_death_callback",
        "__asan_set_error_report_callback",
        "__msan_default_options",
        "__msan_malloc_hook",
        "__msan_free_hook",
        "__msan_unpoison",
        "__msan_unpoison_string",
        "__msan_set_exit_code",
        "__lsan_is_turned_off",
        "__lsan_default_suppressions",
        "__lsan_do_leak_check",
        "__lsan_disable",
        "__lsan_enable",
        "__lsan_ignore_object",
        "__lsan_register_root_region",
        "__lsan_unregister_root_region",
        "__sanitizer_set_death_callback",
        "__sanitizer_set_report_path",
        "__sanitizer_sandbox_on_notify",
    )
)
INVALID_PRIMITIVES = frozenset(("no_sanitize", "disable_sanitizer_instrumentation"))

ASAN_FLAGS = ("-fsanitize=address", "-static-libasan", "-g", "-O0")


TIMEOUT_MESSAGE = """

TIMEOUT! Typically this means the program took too long,
requested more inputs than provided, or an infinite loop was found.
If your program is reading data using scanf inside a loop, this
could also mean that scanf does not support the input provided
(e.g., reading an int if the input is a double).
"""


class UngradableException(Exception):
    def __init__(self):
        pass


class ARMGrader:
    def __init__(self):
        self.assembler = "arm-linux-gnueabihf-as"
        self.linker = "arm-linux-gnueabihf-ld"
        with open(DATAFILE) as file:
            self.data = json.load(file)

    def run_command(self, command, input=None, sandboxed=True, timeout=None, env=None):
        if isinstance(command, str):
            command = shlex.split(command)
        if sandboxed:
            command = [
                "su",
                SB_USER,
                "-s",
                "/bin/bash",
                "-c",
                shlex.join(["PATH=" + self.path] + command),
            ]

        try:
            proc = subprocess.Popen(
                command,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except Exception:
            return ""
        out = None
        tostr = ""
        if input is not None and not isinstance(input, (bytes, bytearray)):
            input = str(input).encode("utf-8")
        try:
            proc.communicate(input=input, timeout=timeout)[0]
        except subprocess.TimeoutExpired:
            tostr = TIMEOUT_MESSAGE
        finally:
            proc.kill()
            try:
                out = proc.communicate(timeout=timeout)[0]
            except subprocess.TimeoutExpired:
                tostr = TIMEOUT_MESSAGE
            finally:
                out = out.decode("utf-8", "backslashreplace") if out else ""
                return out + tostr

    def compile_file(
        self,
        s_files,
        exec_file=None,
        add_warning_result_msg=True,
        ungradable_if_failed=True,
        return_objects=False,
    ):
        if not isinstance(s_files, list):
            s_files = [s_files]
        out = ""
        o_files = []
        for s_file in s_files:
            o_file = pathlib.Path(s_file).with_suffix(".o")
            o_files.append(o_file)
            out += self.run_command(
                [self.assembler, "-c", s_file, "-o", o_file],
                sandboxed=False,
            )
            #if os.path.isfile(o_file):
            # TODO: Check if needed
        if ungradable_if_failed and not all(
            os.path.isfile(f) for f in o_files
        ):
            self.result[
                "message"
            ] += f"Compilation errors, please fix and try again.\n\n{out}\n"
            raise UngradableException()
        if out and add_warning_result_msg:
            self.result["message"] += f"Compilation warnings:\n\n{out}\n"
        if exec_file:
            out += self.link_object_files(
                o_files,
                exec_file,
                add_warning_result_msg=add_warning_result_msg,
                ungradable_if_failed=ungradable_if_failed
            )
        return (out, o_files) if return_objects else out

    def link_object_files(
        self,
        o_files,
        exec_file,
        add_warning_result_msg=True,
        ungradable_if_failed=True
    ):
        out = self.run_command(
            [self.linker]
            + o_files
            + ["-o", exec_file],
            sandboxed=False,
        )

        if os.path.isfile(exec_file):
            self.change_mode(exec_file, "755")
        elif ungradable_if_failed:
            self.result[
                "message"
            ] += f"Linker errors, please fix and try again.\n\n{out}\n"
            raise UngradableException()
        if out and add_warning_result_msg:
            self.result["message"] += f"Linker warnings:\n\n{out}\n"
        return out

    def test_compile_file(
        self,
        s_files,
        exec_file=None,
        points=1,
        field=None,
        name="Compilation",
        add_warning_result_msg=True,
        ungradable_if_failed=True
    ):
        out, objects = self.compile_file(
            s_files,
            exec_file,
            add_warning_result_msg=add_warning_result_msg,
            ungradable_if_failed=ungradable_if_failed,
            return_objects=True
        )
        success = (
            os.path.isfile(exec_file)
            if exec_file
            else all(os.path.isfile(f) for f in objects)
        )
        return self.add_test_result(
            name,
            output=out,
            points=points if success else 0,
            max_points=points,
            field=field,
        )

    def change_mode(self, file, mode="744", change_parent=True):
        file = os.path.abspath(file)
        self.run_command(["chmod", mode, file], sandboxed=False)
        parent = os.path.dirname(file)
        if change_parent and parent and not os.path.samefile(file, parent):
            self.change_mode(parent, "711")

    def generateHeaders(
        self,
        main_file="/grade/tests/main.c",
        generate_rand=256,
        memory_map={},
        functions=None,
    ):
        with open(main_file, 'r') as f:
            main = f.readlines()

        if generate_rand is not None:
            rand_array = [random.randint(0, 65535) for _ in range(generate_rand)]
            main[main.index('#define RAND_SIZE 1\n')] = f'#define RAND_SIZE {generate_rand}\n'
            main[main.index('int RAND_ARRAY[RAND_SIZE];\n')] = f'int RAND_ARRAY[RAND_SIZE] = {{{",".join(map(str,rand_array))}}};\n'
        if functions is not None:
            main.insert(main.index('// functions inserted here\n')+1, ''.join(functions))
        
        for base in memory_map:
            var = memory_map[base]
            if var is None: continue
            adr = 0x2000_0000 | (int(base)<<2)

            name = var['name']
            _type = var['type']

            main[main.index(f'#define {name} *((int *) 0)\n')] = f'#define {name} (*((volatile {_type} *) {adr}))\n'

        with open(main_file, 'w') as f:
            f.write("\n".join(main))

    def make(
        self,
        student_file="student.s",
        show_compilation=True,
        debug=False,
    ):
        self.run_command(f"cp {student_file} /grade/tests/{student_file}", sandboxed=False)
        out = self.run_command(f"make -C /grade/tests {'system.g.bin' if debug else 'system.bin'}", sandboxed=False)
        success = (
            os.path.isfile("/grade/tests/system.g.bin") if debug
            else os.path.isfile("/grade/tests/system.bin")
        )
        if not success:
            self.result['message'] = f'Compilation Errors!\n\n{out}'
            raise UngradableException()
        if show_compilation:
            self.result['message'] = f'Compilation:\n\n{out}'
        return out

    def test_make(
        self,
        student_file="student.s",
        points=1,
        name="Compilation",
        field=None,
    ):
        out = self.make(student_file=student_file)
        success = (
            os.path.isfile("/grade/tests/system.bin") and
            os.path.isfile("/grade/tests/system.g.bin")
        )
        return self.add_test_result(
            name,
            out=out,
            points=points if success else 0,
            max_points=points,
            field=field,
        )

    def test_make_run(
        self,
        input=None,
        exp_output=None,
        must_match_all_outputs=False,  # True, False or 'partial'
        reject_output=None,
        field=None,
        ignore_case=True,
        timeout=1,
        size_limit=10240,
        ignore_consec_spaces=True,
        args=None,
        name=None,
        msg=None,
        max_points=1,
        highlight_matches=False, 
    ):  
        self.change_mode("/grade/tests/system.bin", "555")
        return self.test_run(
            "qemu-system-arm -M lm3s6965evb -semihosting -nographic -kernel /grade/tests/system.bin",
            input=input,
            exp_output=exp_output,
            must_match_all_outputs=must_match_all_outputs,
            reject_output=reject_output,
            field=field,
            ignore_case=ignore_case,
            timeout=timeout,
            size_limit=size_limit,
            ignore_consec_spaces=ignore_consec_spaces,
            args=args,
            name=name,
            msg=msg,
            max_points=max_points,
            highlight_matches=highlight_matches
        )


    def dump_registers(
        self,
        executable,
        port=1000,
        output_filename='run.txt',
        breakpoint='exit',
    ):
        self.run_command(f"touch {output_filename} && chmod 777 {output_filename}", sandboxed=False)
        self.run_command(
            f"qemu-arm -g {port} {executable} & gdb-multiarch {executable} -ex 'target remote localhost:{port}' -ex 'b {breakpoint}' -ex 'c' -ex 'info reg' -ex 'c' -ex 'exit' > {output_filename}",
        )

    def test_qemu(
        self,
        command,
        input=None,
        exp_output=None,
        must_match_all_outputs=False,  # True, False or 'partial'
        reject_output=None,
        field=None,
        ignore_case=True,
        timeout=1,
        size_limit=10240,
        ignore_consec_spaces=True,
        args=None,
        name=None,
        msg=None,
        max_points=1,
        highlight_matches=False, 
    ):
        return self.test_run(
            "qemu-arm",
            input=input,
            exp_output=exp_output,
            must_match_all_outputs=must_match_all_outputs,
            reject_output=reject_output,
            field=field,
            ignore_case=ignore_case,
            timeout=timeout,
            size_limit=size_limit,
            ignore_consec_spaces=ignore_consec_spaces,
            args=[command] if args is None else [command] + args,
            name=name,
            msg=msg,
            max_points=max_points,
            highlight_matches=highlight_matches
        )

    def test_run(
        self,
        command,
        input=None,
        exp_output=None,
        must_match_all_outputs=False,  # True, False or 'partial'
        reject_output=None,
        field=None,
        ignore_case=True,
        timeout=1,
        size_limit=10240,
        ignore_consec_spaces=True,
        args=None,
        name=None,
        msg=None,
        max_points=1,
        highlight_matches=False,
    ):
        if args is not None:
            if not isinstance(args, list):
                args = [args]
            args = list(map(str, args))

        if name is None and input is not None:
            name = 'Test with input "%s"' % " ".join(input.splitlines())
        elif name is None and args is not None:
            name = 'Test with arguments "%s"' % " ".join(args)
        elif name is None and isinstance(command, list):
            name = "Test command: %s" % command[0]
        elif name is None:
            name = "Test command: %s" % command

        if exp_output is None:
            exp_output = []
            must_match_all_outputs = True
        elif not isinstance(exp_output, list):
            exp_output = [exp_output]

        if reject_output is None:
            reject_output = []
        elif not isinstance(reject_output, list):
            reject_output = [reject_output]

        def compile_re(t):
            if isinstance(t, re.Pattern):
                return (t.pattern, t)
            # If t is not a string, convert it to its string representation
            t = str(t)
            return (
                t.strip(),
                re.compile(
                    (
                        "\\s+".join(map(re.escape, re.split("\\s+", t)))
                        if ignore_consec_spaces
                        else re.escape(t)
                    ),
                    re.I if ignore_case else 0,
                ),
            )

        exp_output = [compile_re(t) for t in exp_output]
        reject_output = [compile_re(t) for t in reject_output]

        out = self.run_command(
            command if args is None else ([command] + args),
            input,
            sandboxed=True,
            timeout=timeout,
        )

        outcmp = out
        if highlight_matches and out:
            for _, r in exp_output:
                out = r.sub(r"\033[32m\g<0>\033[0m", out)
            for _, r in reject_output:
                out = r.sub(r"\033[31m\g<0>\033[0m", out)
        if not out:
            out = "(NO OUTPUT)"
        elif not out.endswith("\n"):
            out += "\n(NO ENDING LINE BREAK)"

        if msg is None and exp_output:
            comment = (
                ""
                if len(exp_output) == 1
                else " all of" if must_match_all_outputs else " one of"
            )
            join_str = "\n\n" if any("\n" in t for t, _ in exp_output) else "\n\t"
            msg = f"Expected{comment}:{join_str}" + join_str.join(
                (
                    f"\033[32m{t}\033[0m"
                    if highlight_matches and r.search(outcmp) is not None
                    else t
                )
                for t, r in exp_output
            )
            if reject_output:
                join_str = (
                    "\n\n" if any("\n" in t for t, _ in reject_output) else "\n\t"
                )
                msg += f"\nBut not:{join_str}" + join_str.join(
                    (
                        f"\033[31m{t}\033[0m"
                        if highlight_matches and r.search(outcmp) is not None
                        else t
                    )
                    for t, r in reject_output
                )
        elif msg is None:
            msg = ""

        points = max_points
        if timeout and "TIMEOUT" in outcmp:
            points = 0
        elif size_limit and len(outcmp) > size_limit:
            out = out[0:size_limit] + "\nTRUNCATED: Output too long."
            points = 0
        elif any(r.search(outcmp) is not None for _, r in reject_output):
            points = 0
        elif must_match_all_outputs == "partial":
            points = (
                max_points
                * sum(1 if r.search(outcmp) is not None else 0 for _, r in exp_output)
                / len(exp_output)
            )
        elif not (all if must_match_all_outputs else any)(
            r.search(outcmp) is not None for _, r in exp_output
        ):
            points = 0

        return self.add_test_result(
            name,
            points=points,
            msg=msg,
            output=out,
            max_points=max_points,
            field=field,
        )

    def add_manual_grading(self, points=1, name=None, description=None):
        """Old deprecated function, retained for compatibility reasons."""
        if not name:
            name = "Manual Grading - to be reviewed by a human grader"
        if not description:
            description = "This code will be manually reviewed by a human grader. The points associated to this component will be added based on evaluation of code style, programming practices and other manully checked criteria."
        return self.add_test_result(name, description, points=0, max_points=points)

    def add_test_result(
        self,
        name,
        description="",
        points=True,
        msg="",
        output="",
        max_points=1,
        field=None,
        images=None,
    ):
        if not isinstance(points, (int, float)):
            points = max_points if points else 0.0
        test = {
            "name": name,
            "description": description,
            "points": points,
            "max_points": max_points,
            "output": output,
            "message": msg if msg else "",
        }
        if images and isinstance(images, list):
            test["images"] = images
        elif images:
            test["images"] = [images]
        self.result["tests"].append(test)
        self.result["points"] += points
        self.result["max_points"] += max_points

        if field is not None:
            if "partial_scores" not in self.result:
                self.result["partial_scores"] = {}
            if field not in self.result["partial_scores"]:
                self.result["partial_scores"][field] = {
                    "points": points,
                    "max_points": max_points,
                }
            else:
                self.result["partial_scores"][field]["points"] += points
                self.result["partial_scores"][field]["max_points"] += max_points
        return test

    def save_results(self):
        if self.result["max_points"] > 0:
            self.result["score"] = self.result["points"] / self.result["max_points"]
        if "partial_scores" in self.result:
            for field, ps in self.result["partial_scores"].items():
                ps["score"] = ps["points"] / ps["max_points"]

        if not os.path.exists("/grade/results"):
            os.makedirs("/grade/results")
        with open("/grade/results/results.json", "w") as resfile:
            json.dump(self.result, resfile)

    def start(self):
        self.result = {
            "score": 0.0,
            "points": 0,
            "max_points": 0,
            "output": "",
            "message": "",
            "gradable": True,
            "tests": [],
        }

        os.chdir(CODEBASE)

        self.path = "/armgrader:" + os.environ["PATH"]

        self.run_command("chmod -R 700 /grade", sandboxed=False)

        try:
            self.tests()
        except UngradableException:
            self.result["gradable"] = False
        finally:
            self.save_results()

    def tests(self):
        pass


if __name__ == "__main__":
    ARMGrader().start()
