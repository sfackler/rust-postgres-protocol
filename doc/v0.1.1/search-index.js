var searchIndex = {};
searchIndex["postgres_protocol"] = {"doc":"Low level Postgres protocol APIs.","items":[[4,"IsNull","postgres_protocol","An enum indicating if a value is `NULL` or not.",null,null],[13,"Yes","","The value is `NULL`.",0,null],[13,"No","","The value is not `NULL`.",0,null],[0,"authentication","","Authentication protocol support.",null,null],[5,"md5_hash","postgres_protocol::authentication","Hashes authentication information in a way suitable for use in response\nto an `AuthenticationMd5Password` message.",null,null],[0,"message","postgres_protocol","Postgres message protocol support.",null,null],[0,"backend","postgres_protocol::message","Backend message deserialization.",null,null],[3,"RowDescriptionEntry","postgres_protocol::message::backend","",null,null],[12,"name","","",1,null],[12,"table_oid","","",1,null],[12,"column_id","","",1,null],[12,"type_oid","","",1,null],[12,"type_size","","",1,null],[12,"type_modifier","","",1,null],[12,"format","","",1,null],[4,"Message","","An enum representing Postgres backend messages.",null,null],[13,"AuthenticationCleartextPassword","","",2,null],[13,"AuthenticationGSS","","",2,null],[13,"AuthenticationKerberosV5","","",2,null],[13,"AuthenticationMD5Password","","",2,null],[12,"salt","postgres_protocol::message::backend::Message","",2,null],[13,"AuthenticationOk","postgres_protocol::message::backend","",2,null],[13,"AuthenticationSCMCredential","","",2,null],[13,"AuthenticationSSPI","","",2,null],[13,"BackendKeyData","","",2,null],[12,"process_id","postgres_protocol::message::backend::Message","",2,null],[12,"secret_key","","",2,null],[13,"BindComplete","postgres_protocol::message::backend","",2,null],[13,"CloseComplete","","",2,null],[13,"CommandComplete","","",2,null],[12,"tag","postgres_protocol::message::backend::Message","",2,null],[13,"CopyData","postgres_protocol::message::backend","",2,null],[12,"data","postgres_protocol::message::backend::Message","",2,null],[13,"CopyDone","postgres_protocol::message::backend","",2,null],[13,"CopyInResponse","","",2,null],[12,"format","postgres_protocol::message::backend::Message","",2,null],[12,"column_formats","","",2,null],[13,"CopyOutResponse","postgres_protocol::message::backend","",2,null],[12,"format","postgres_protocol::message::backend::Message","",2,null],[12,"column_formats","","",2,null],[13,"DataRow","postgres_protocol::message::backend","",2,null],[12,"row","postgres_protocol::message::backend::Message","",2,null],[13,"EmptyQueryResponse","postgres_protocol::message::backend","",2,null],[13,"ErrorResponse","","",2,null],[12,"fields","postgres_protocol::message::backend::Message","",2,null],[13,"NoData","postgres_protocol::message::backend","",2,null],[13,"NoticeResponse","","",2,null],[12,"fields","postgres_protocol::message::backend::Message","",2,null],[13,"NotificationResponse","postgres_protocol::message::backend","",2,null],[12,"process_id","postgres_protocol::message::backend::Message","",2,null],[12,"channel","","",2,null],[12,"payload","","",2,null],[13,"ParameterDescription","postgres_protocol::message::backend","",2,null],[12,"types","postgres_protocol::message::backend::Message","",2,null],[13,"ParameterStatus","postgres_protocol::message::backend","",2,null],[12,"parameter","postgres_protocol::message::backend::Message","",2,null],[12,"value","","",2,null],[13,"ParseComplete","postgres_protocol::message::backend","",2,null],[13,"PortalSuspended","","",2,null],[13,"ReadyForQuery","","",2,null],[12,"state","postgres_protocol::message::backend::Message","",2,null],[13,"RowDescription","postgres_protocol::message::backend","",2,null],[12,"descriptions","postgres_protocol::message::backend::Message","",2,null],[4,"ParseResult","postgres_protocol::message::backend","The result of an attempted parse.",null,null],[13,"Complete","","A message was successfully parsed.",3,null],[12,"message","postgres_protocol::message::backend::ParseResult","The message.",3,null],[12,"consumed","","The number of bytes of the input buffer consumed to parse this message.",3,null],[13,"Incomplete","postgres_protocol::message::backend","The buffer did not contain a full message.",3,null],[12,"required_size","postgres_protocol::message::backend::ParseResult","The number of total bytes required to parse a message, if known.",3,null],[0,"borrowed","postgres_protocol::message::backend","An allocation-free backend message parser.",null,null],[3,"AuthenticationMd5PasswordBody","postgres_protocol::message::backend::borrowed","",null,null],[3,"BackendKeyDataBody","","",null,null],[3,"CommandCompleteBody","","",null,null],[3,"CopyDataBody","","",null,null],[3,"CopyInResponseBody","","",null,null],[3,"ColumnFormats","","",null,null],[3,"CopyOutResponseBody","","",null,null],[3,"DataRowBody","","",null,null],[3,"DataRowValues","","",null,null],[3,"ErrorResponseBody","","",null,null],[3,"ErrorFields","","",null,null],[3,"ErrorField","","",null,null],[3,"NoticeResponseBody","","",null,null],[3,"NotificationResponseBody","","",null,null],[3,"ParameterDescriptionBody","","",null,null],[3,"Parameters","","",null,null],[3,"ParameterStatusBody","","",null,null],[3,"ReadyForQueryBody","","",null,null],[3,"RowDescriptionBody","","",null,null],[3,"Fields","","",null,null],[3,"Field","","",null,null],[4,"Message","","An enum representing Postgres backend messages.",null,null],[13,"AuthenticationCleartextPassword","","",4,null],[13,"AuthenticationGss","","",4,null],[13,"AuthenticationKerberosV5","","",4,null],[13,"AuthenticationMd55Password","","",4,null],[13,"AuthenticationOk","","",4,null],[13,"AuthenticationScmCredential","","",4,null],[13,"AuthenticationSspi","","",4,null],[13,"BackendKeyData","","",4,null],[13,"BindComplete","","",4,null],[13,"CloseComplete","","",4,null],[13,"CommandComplete","","",4,null],[13,"CopyData","","",4,null],[13,"CopyDone","","",4,null],[13,"CopyInResponse","","",4,null],[13,"CopyOutResponse","","",4,null],[13,"DataRow","","",4,null],[13,"EmptyQueryResponse","","",4,null],[13,"ErrorResponse","","",4,null],[13,"NoData","","",4,null],[13,"NoticeResponse","","",4,null],[13,"NotificationResponse","","",4,null],[13,"ParameterDescription","","",4,null],[13,"ParameterStatus","","",4,null],[13,"ParseComplete","","",4,null],[13,"PortalSuspended","","",4,null],[13,"ReadyForQuery","","",4,null],[13,"RowDescription","","",4,null],[11,"parse","","Attempts to deserialize a backend message from the buffer.",4,null],[11,"to_owned","","Converts this message into an owned representation.",4,null],[11,"salt","","",5,null],[11,"process_id","","",6,null],[11,"secret_key","","",6,null],[11,"tag","","",7,null],[11,"data","","",8,null],[11,"format","","",9,null],[11,"column_formats","","",9,null],[11,"next","","",10,null],[11,"size_hint","","",10,null],[11,"format","","",11,null],[11,"column_formats","","",11,null],[11,"values","","",12,null],[11,"next","","",13,null],[11,"size_hint","","",13,null],[11,"fields","","",14,null],[11,"next","","",15,null],[11,"type_","","",16,null],[11,"value","","",16,null],[11,"fields","","",17,null],[11,"process_id","","",18,null],[11,"channel","","",18,null],[11,"message","","",18,null],[11,"parameters","","",19,null],[11,"next","","",20,null],[11,"size_hint","","",20,null],[11,"name","","",21,null],[11,"value","","",21,null],[11,"status","","",22,null],[11,"fields","","",23,null],[11,"next","","",24,null],[11,"name","","",25,null],[11,"table_oid","","",25,null],[11,"column_id","","",25,null],[11,"type_oid","","",25,null],[11,"type_size","","",25,null],[11,"type_modifier","","",25,null],[11,"format","","",25,null],[11,"parse","postgres_protocol::message::backend","Attempts to deserialize a backend message from the buffer.",2,null],[0,"frontend","postgres_protocol::message","Frontend message serialization.",null,null],[4,"Message","postgres_protocol::message::frontend","",null,null],[13,"Bind","","",26,null],[12,"portal","postgres_protocol::message::frontend::Message","",26,null],[12,"statement","","",26,null],[12,"formats","","",26,null],[12,"values","","",26,null],[12,"result_formats","","",26,null],[13,"CancelRequest","postgres_protocol::message::frontend","",26,null],[12,"process_id","postgres_protocol::message::frontend::Message","",26,null],[12,"secret_key","","",26,null],[13,"Close","postgres_protocol::message::frontend","",26,null],[12,"variant","postgres_protocol::message::frontend::Message","",26,null],[12,"name","","",26,null],[13,"CopyData","postgres_protocol::message::frontend","",26,null],[12,"data","postgres_protocol::message::frontend::Message","",26,null],[13,"CopyDone","postgres_protocol::message::frontend","",26,null],[13,"CopyFail","","",26,null],[12,"message","postgres_protocol::message::frontend::Message","",26,null],[13,"Describe","postgres_protocol::message::frontend","",26,null],[12,"variant","postgres_protocol::message::frontend::Message","",26,null],[12,"name","","",26,null],[13,"Execute","postgres_protocol::message::frontend","",26,null],[12,"portal","postgres_protocol::message::frontend::Message","",26,null],[12,"max_rows","","",26,null],[13,"Parse","postgres_protocol::message::frontend","",26,null],[12,"name","postgres_protocol::message::frontend::Message","",26,null],[12,"query","","",26,null],[12,"param_types","","",26,null],[13,"PasswordMessage","postgres_protocol::message::frontend","",26,null],[12,"password","postgres_protocol::message::frontend::Message","",26,null],[13,"Query","postgres_protocol::message::frontend","",26,null],[12,"query","postgres_protocol::message::frontend::Message","",26,null],[13,"SslRequest","postgres_protocol::message::frontend","",26,null],[13,"StartupMessage","","",26,null],[12,"parameters","postgres_protocol::message::frontend::Message","",26,null],[13,"Sync","postgres_protocol::message::frontend","",26,null],[13,"Terminate","","",26,null],[4,"BindError","","",null,null],[13,"Conversion","","",27,null],[13,"Serialization","","",27,null],[5,"bind","","",null,{"inputs":[{"name":"str"},{"name":"str"},{"name":"i"},{"name":"j"},{"name":"f"},{"name":"k"},{"name":"vec"}],"output":{"name":"result"}}],[5,"cancel_request","","",null,{"inputs":[{"name":"i32"},{"name":"i32"},{"name":"vec"}],"output":null}],[5,"close","","",null,{"inputs":[{"name":"u8"},{"name":"str"},{"name":"vec"}],"output":{"name":"result"}}],[5,"copy_data","","",null,null],[5,"copy_done","","",null,{"inputs":[{"name":"vec"}],"output":null}],[5,"copy_fail","","",null,{"inputs":[{"name":"str"},{"name":"vec"}],"output":{"name":"result"}}],[5,"describe","","",null,{"inputs":[{"name":"u8"},{"name":"str"},{"name":"vec"}],"output":{"name":"result"}}],[5,"execute","","",null,{"inputs":[{"name":"str"},{"name":"i32"},{"name":"vec"}],"output":{"name":"result"}}],[5,"parse","","",null,{"inputs":[{"name":"str"},{"name":"str"},{"name":"i"},{"name":"vec"}],"output":{"name":"result"}}],[5,"password_message","","",null,{"inputs":[{"name":"str"},{"name":"vec"}],"output":{"name":"result"}}],[5,"query","","",null,{"inputs":[{"name":"str"},{"name":"vec"}],"output":{"name":"result"}}],[5,"ssl_request","","",null,{"inputs":[{"name":"vec"}],"output":null}],[5,"startup_message","","",null,{"inputs":[{"name":"i"},{"name":"vec"}],"output":{"name":"result"}}],[5,"sync","","",null,{"inputs":[{"name":"vec"}],"output":null}],[5,"terminate","","",null,{"inputs":[{"name":"vec"}],"output":null}],[11,"serialize","","",26,null],[11,"from","","",27,{"inputs":[{"name":"box"}],"output":{"name":"binderror"}}],[11,"from","","",27,{"inputs":[{"name":"error"}],"output":{"name":"binderror"}}],[0,"types","postgres_protocol","Conversions to and from Postgres&#39;s binary format for various types.",null,null],[3,"HstoreEntries","postgres_protocol::types","A fallible iterator over `HSTORE` entries.",null,null],[3,"Varbit","","A `VARBIT` value.",null,null],[3,"Array","","A Postgres array.",null,null],[3,"ArrayDimensions","","An iterator over the dimensions of an array.",null,null],[3,"ArrayDimension","","Information about a dimension of an array.",null,null],[12,"len","","The length of this dimension.",28,null],[12,"lower_bound","","The base value used to index into this dimension.",28,null],[3,"ArrayValues","","An iterator over the values of an array, in row-major order.",null,null],[4,"RangeBound","","One side of a range.",null,null],[13,"Inclusive","","An inclusive bound.",29,null],[13,"Exclusive","","An exclusive bound.",29,null],[13,"Unbounded","","No bound.",29,null],[4,"Range","","A Postgres range.",null,null],[13,"Empty","","An empty range.",30,null],[13,"Nonempty","","A nonempty range.",30,null],[5,"bool_to_sql","","Serializes a `BOOL` value.",null,{"inputs":[{"name":"bool"},{"name":"vec"}],"output":null}],[5,"bool_from_sql","","Deserializes a `BOOL` value.",null,null],[5,"bytea_to_sql","","Serializes a `BYTEA` value.",null,null],[5,"bytea_from_sql","","Deserializes a `BYTEA value.",null,null],[5,"text_to_sql","","Serializes a `TEXT`, `VARCHAR`, `CHAR(n)`, `NAME`, or `CITEXT` value.",null,{"inputs":[{"name":"str"},{"name":"vec"}],"output":null}],[5,"text_from_sql","","Deserializes a `TEXT`, `VARCHAR`, `CHAR(n)`, `NAME`, or `CITEXT` value.",null,null],[5,"char_to_sql","","Serializes a `&quot;char&quot;` value.",null,{"inputs":[{"name":"i8"},{"name":"vec"}],"output":null}],[5,"char_from_sql","","Deserializes a `&quot;char&quot;` value.",null,null],[5,"int2_to_sql","","Serializes an `INT2` value.",null,{"inputs":[{"name":"i16"},{"name":"vec"}],"output":null}],[5,"int2_from_sql","","Deserializes an `INT2` value.",null,null],[5,"int4_to_sql","","Serializes an `INT4` value.",null,{"inputs":[{"name":"i32"},{"name":"vec"}],"output":null}],[5,"int4_from_sql","","Deserializes an `INT4` value.",null,null],[5,"oid_to_sql","","Serializes an `OID` value.",null,{"inputs":[{"name":"oid"},{"name":"vec"}],"output":null}],[5,"oid_from_sql","","Deserializes an `OID` value.",null,null],[5,"int8_to_sql","","Serializes an `INT8` value.",null,{"inputs":[{"name":"i64"},{"name":"vec"}],"output":null}],[5,"int8_from_sql","","Deserializes an `INT8` value.",null,null],[5,"float4_to_sql","","Serializes a `FLOAT4` value.",null,{"inputs":[{"name":"f32"},{"name":"vec"}],"output":null}],[5,"float4_from_sql","","Deserializes a `FLOAT4` value.",null,null],[5,"float8_to_sql","","Serializes a `FLOAT8` value.",null,{"inputs":[{"name":"f64"},{"name":"vec"}],"output":null}],[5,"float8_from_sql","","Deserializes a `FLOAT8` value.",null,null],[5,"hstore_to_sql","","Serializes an `HSTORE` value.",null,{"inputs":[{"name":"i"},{"name":"vec"}],"output":{"name":"result"}}],[5,"hstore_from_sql","","Deserializes an `HSTORE` value.",null,null],[5,"varbit_to_sql","","Serializes a `VARBIT` or `BIT` value.",null,{"inputs":[{"name":"usize"},{"name":"i"},{"name":"vec"}],"output":{"name":"result"}}],[5,"varbit_from_sql","","Deserializes a `VARBIT` or `BIT` value.",null,null],[5,"timestamp_to_sql","","Serializes a `TIMESTAMP` or `TIMESTAMPTZ` value.",null,{"inputs":[{"name":"i64"},{"name":"vec"}],"output":null}],[5,"timestamp_from_sql","","Deserializes a `TIMESTAMP` or `TIMESTAMPTZ` value.",null,null],[5,"date_to_sql","","Serializes a `DATE` value.",null,{"inputs":[{"name":"i32"},{"name":"vec"}],"output":null}],[5,"date_from_sql","","Deserializes a `DATE` value.",null,null],[5,"time_to_sql","","Serializes a `TIME` or `TIMETZ` value.",null,{"inputs":[{"name":"i64"},{"name":"vec"}],"output":null}],[5,"time_from_sql","","Deserializes a `TIME` or `TIMETZ` value.",null,null],[5,"macaddr_to_sql","","Serializes a `MACADDR` value.",null,null],[5,"macaddr_from_sql","","Deserializes a `MACADDR` value.",null,null],[5,"uuid_to_sql","","Serializes a `UUID` value.",null,null],[5,"uuid_from_sql","","Deserializes a `UUID` value.",null,null],[5,"array_to_sql","","Serializes an array value.",null,{"inputs":[{"name":"i"},{"name":"bool"},{"name":"oid"},{"name":"j"},{"name":"f"},{"name":"vec"}],"output":{"name":"result"}}],[5,"array_from_sql","","Deserializes an array value.",null,null],[5,"empty_range_to_sql","","Serializes an empty range.",null,{"inputs":[{"name":"vec"}],"output":null}],[5,"range_to_sql","","Serializes a range value.",null,{"inputs":[{"name":"f"},{"name":"g"},{"name":"vec"}],"output":{"name":"result"}}],[5,"range_from_sql","","Deserializes a range value.",null,null],[11,"next","","",31,null],[11,"size_hint","","",31,null],[11,"len","","Returns the number of bits.",32,null],[11,"bytes","","Returns the bits as a slice of bytes.",32,null],[11,"has_nulls","","Returns true if there are `NULL` elements.",33,null],[11,"element_type","","Returns the OID of the elements of the array.",33,null],[11,"dimensions","","Returns an iterator over the dimensions of the array.",33,null],[11,"values","","Returns an iterator over the values of the array.",33,null],[11,"next","","",34,null],[11,"size_hint","","",34,null],[11,"fmt","","",28,null],[11,"clone","","",28,null],[11,"eq","","",28,null],[11,"ne","","",28,null],[11,"next","","",35,null],[11,"size_hint","","",35,null],[6,"Oid","postgres_protocol","A Postgres OID.",null,null]],"paths":[[4,"IsNull"],[3,"RowDescriptionEntry"],[4,"Message"],[4,"ParseResult"],[4,"Message"],[3,"AuthenticationMd5PasswordBody"],[3,"BackendKeyDataBody"],[3,"CommandCompleteBody"],[3,"CopyDataBody"],[3,"CopyInResponseBody"],[3,"ColumnFormats"],[3,"CopyOutResponseBody"],[3,"DataRowBody"],[3,"DataRowValues"],[3,"ErrorResponseBody"],[3,"ErrorFields"],[3,"ErrorField"],[3,"NoticeResponseBody"],[3,"NotificationResponseBody"],[3,"ParameterDescriptionBody"],[3,"Parameters"],[3,"ParameterStatusBody"],[3,"ReadyForQueryBody"],[3,"RowDescriptionBody"],[3,"Fields"],[3,"Field"],[4,"Message"],[4,"BindError"],[3,"ArrayDimension"],[4,"RangeBound"],[4,"Range"],[3,"HstoreEntries"],[3,"Varbit"],[3,"Array"],[3,"ArrayDimensions"],[3,"ArrayValues"]]};
initSearch(searchIndex);
