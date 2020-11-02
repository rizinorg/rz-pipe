(** Interact with rizin, ideal for utop interaction *)

(** A running instance of rz *)
type rz

(** Send a command to rz, get back plain string output *)
val command : rz:rz -> string -> string

(** Send a command to rz, get back Yojson. If output isn't JSON
    parsable then raises {Invalid_argument} so make sure command ends
    with 'j' *)
val command_json : rz:rz -> string -> Yojson.t

(** Create a rz instance with a given file, raises {Invalid_argument}
    if file doesn't exists *)
val open_file : string -> rz

(** close a rz instance *)
val close : rz -> unit

(** Convenience function for opening a rz instance, sending a command,
    getting the result as plain string and closing the rz instance *)
val with_command : cmd:string -> string -> string

(** Convenience function for opening a rz instance, sending a command,
    getting the result as Yojson and closing the rz instance *)
val with_command_j : cmd:string -> string -> Yojson.t
