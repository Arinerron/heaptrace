typedef enum UBPTType {UBPT_TYPE_IDENTIFIER, UBPT_TYPE_PUNCTUATOR} UBPTType;

typedef struct UserBreakpointToken {
    UBPTType type;
    char *value;
    size_t i; // index in the parsed str of the start of the token
    struct UserBreakpointToken *next;
} UserBreakpointToken;


typedef enum UBPAOperation {UBPA_OPERATION_ADD, UBPA_OPERATION_SUBTRACT} UBPAOperation;

typedef struct UserBreakpointAddress {
    UBPAOperation operation; // + or -

    // it will use address if !symbol_name only (define one or the other)
    char *symbol_name; // variable
    uint64_t address; // literal

    struct UserBreakpointAddress *next_operation; // next operation in the expression
} UserBreakpointAddress;


typedef enum UBPWhen {UBP_WHEN_BEFORE, UBP_WHEN_AFTER} UBPWhen;
typedef enum UBPWhat {UBP_WHAT_OID, UBP_WHAT_ADDRESS, UBP_WHAT_SEGFAULT, UBP_WHAT_ENTRY} UBPWhat;

typedef struct UserBreakpoint {
    // unparsed instructions
    char *name;

    // data for breakpoint-determining logic
    UBPWhat what;
    UBPWhen when; // [UBP_WHEN_BEFORE, UBP_WHEN_AFTER]
    size_t count;

    // extra storage fields
    int oid;
    UserBreakpointAddress *address;

    // next &&/AND instruction
    // struct UserBreakpoint *next_requirement;
    // XXX: AND not supported yet

    // next ||/OR instruction
    struct UserBreakpoint *next;

    // runtime things...
    size_t h_i;
} UserBreakpoint;


extern UserBreakpoint *USER_BREAKPOINT_HEAD;

UserBreakpointToken *tokenize_user_breakpoint_str(char *breakpoint);
UserBreakpoint *create_user_breakpoint(char *name);
void free_user_breakpoints();
void check_should_break(HeaptraceContext *ctx);


/*
 * --break 'address=bin+0x1234:10'
 *
 *
 *  WOULD BE CONVERTED INTO THE TOKEN LIST:
 *
 *
 *  type  = UBPT_TYPE_IDENTIFIER
 *  value = address
 *
 * type  = UBPT_TYPE_PUNCTUATOR
 * value = =
 *
 * type  = UBPT_TYPE_IDENTIFIER
 * value = bin
 *
 * type  = UBPT_TYPE_PUNCTUATOR
 * value = +
 *
 * type  = UBPT_TYPE_IDENTIFIER
 * value = 0x1234
 *
 * type  = UBPT_TYPE_PUNCTUATOR
 * value = :
 *
 * type  = UBPT_TYPE_IDENTIFIER
 * value = 10
 *
 *
 * WHICH WOULD THEN BE CONVERTED INTO THIS BREAKPOINT STRUCT:
 *
 *
 * bp = UserBreakpoint {
 *      .name="address=bin+0x1234:10",
 *      .when=UBP_WHEN_BEFORE,
 *      .what=UBP_WHAT_ADDRESS,
 *      .count=10,
 *      .address=UserBreakpointAddress {
 *           .operation=UBPA_OPERATION_ADD,
 *           .symbol_name="bin",
 *    .      .next_operation=UserBreakpointAddress {
 *               .operation=UBPA_OPERATION_ADD,
 *               .address=0x1234
 *           }
 *      }
 * }
 *
 */
