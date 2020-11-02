
type rz = {
  to_rz : out_channel;
  of_rz : in_channel;
  err : in_channel;
}

let bufsize = 512

let find_null data ~pos ~len =
  let rec find pos =
    if pos < len
    then if Bytes.get data pos = '\000'
      then Some pos else find (pos+1)
    else None in
  find pos

exception No_input

let fdr rz = Unix.descr_of_in_channel rz.of_rz

let rec read_spin fd data =
  match Unix.read fd data 0 (Bytes.length data) with
  | exception (Unix.Unix_error ((Unix.EAGAIN | EWOULDBLOCK),_,_)) ->
    read_spin fd data
  | 0 -> raise No_input
  | n -> n

let read rz =
  let buf = Buffer.create bufsize in
  let data = Bytes.create bufsize in
  let rec fill () =
    let len = read_spin (fdr rz) data in
    match find_null data ~pos:0 ~len with
    | None -> Buffer.add_subbytes buf data 0 len; fill ()
    | Some pos -> Buffer.add_subbytes buf data 0 pos in
  fill ();
  Buffer.contents buf

let send_command rz cmd =
  Printf.fprintf rz.to_rz "%s\n%!" cmd;
  read rz

let command ~rz cmd = send_command rz cmd

let parse_json s =
  (Yojson.Safe.from_string s :> Yojson.t)

let command_json ~rz cmd =
  try
    send_command rz cmd |> parse_json
  with
    Yojson.Json_error _ ->
    raise (Invalid_argument "Output wasn't JSON parsable, \
                             make sure you used /j")

module Version : sig
  val supported : unit Lazy.t
end
= struct
  let system_error msg =
    invalid_arg ("Failed to run rizin: " ^ Unix.error_message msg)

  let try_finally f x ~finally =
    try let r = f x in finally x; r
    with exn -> finally x; raise exn

  let read_version () =
    match Unix.open_process_in "rizin -qv" with
    | exception Unix.Unix_error (msg,_,_) -> system_error msg
    | output -> try_finally input_line output
                  ~finally:close_in

  let extract_number str pos len =
    try int_of_string (String.sub str pos len)
    with Failure _ -> invalid_arg "invalid version format"

  let parse ver =
    let len = String.length ver in
    match String.index ver '.' with
    | exception Not_found -> extract_number ver 0 len,0
    | pos ->
      extract_number ver 0 pos,
      if pos = len - 1 then 0
      else match String.index_from ver (pos+1) '.' with
        | exception Not_found ->
          if pos = len - 1 then 0
          else extract_number ver (pos+1) (len-pos-1)
        | dot ->
          extract_number ver (pos+1) (dot-pos-1)

  let supported = lazy begin
    let version = parse @@ read_version () in
    if version < (2,3)
    then invalid_arg "incompatible rizin version: please install rz >= 2.3.0"
  end
end

let close ({of_rz; to_rz; err} as rz) =
  let _ : string = command ~rz "q" in
  match Unix.close_process_full (of_rz, to_rz, err) with
  | Unix.WEXITED 0 -> ()
  | Unix.WEXITED n ->
    failwith ("rizin terminated with a non-zero exit code: " ^
              string_of_int n)
  | Unix.WSIGNALED _
  | Unix.WSTOPPED _ -> failwith "rizin was killed"

let readall ch =
  let buf = Buffer.create bufsize in
  let rec read () = Buffer.add_channel buf ch bufsize; read () in
  try read () with End_of_file -> Buffer.contents buf

let open_file f_name =
  let lazy () = Version.supported in
  if not (Sys.file_exists f_name) then
    raise (Invalid_argument "Non-existent file")
  else
    let env = Unix.environment () in
    let cmd = Printf.sprintf "rizin -q0 %s" f_name in
    let of_rz, to_rz, err = Unix.open_process_full cmd env in
    Unix.set_nonblock (Unix.descr_of_in_channel of_rz);
    let rz = {of_rz; to_rz; err} in
    match read rz with
    | exception No_input ->
      let problem = readall err in
      let _ : Unix.process_status =
        Unix.close_process_full (of_rz, to_rz, err) in
      invalid_arg ("Failed to start rizin process: " ^ problem)
    | "" -> rz
    | s ->
      close rz;
      failwith ("spurious output on open: " ^ s)

let with_command ~cmd f_name =
  let rz = open_file f_name in
  let output = command ~rz cmd in
  close rz;
  output

let with_command_j ~cmd f_name =
  let rz = open_file f_name in
  let output = command ~rz cmd in
  close rz;
  output |> parse_json
