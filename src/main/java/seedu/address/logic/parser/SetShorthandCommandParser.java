package seedu.address.logic.parser;

import static seedu.address.logic.Messages.MESSAGE_INVALID_COMMAND_FORMAT;
import static seedu.address.logic.parser.CliSyntax.PREFIX_ORIGINAL_COMMAND;
import static seedu.address.logic.parser.CliSyntax.PREFIX_SHORTHAND;

import java.util.stream.Stream;

import seedu.address.logic.commands.SetShorthandCommand;
import seedu.address.logic.parser.exceptions.ParseException;

/**
 * Parses input arguments and creates a new SetShorthandCommand object
 */
public class SetShorthandCommandParser implements Parser<SetShorthandCommand> {

    public static final String MESSAGE_INVALID_SHORTHAND = "Invalid shorthand! "
                + "Command shorthands must have at least one character "
                + "and must only contain letters from the English alphabet.";


    /**
     * Parses the given {@code String} of arguments in the context of the SetShorthandCommand
     * and returns a SetShorthandCommand object for execution.
     * @throws ParseException if the user input does not conform the expected format
     */
    public SetShorthandCommand parse(String args) throws ParseException {
        ArgumentMultimap argMultimap =
                ArgumentTokenizer.tokenize(args, PREFIX_ORIGINAL_COMMAND, PREFIX_SHORTHAND);

        if (!arePrefixesPresent(argMultimap, PREFIX_ORIGINAL_COMMAND, PREFIX_SHORTHAND)
                || !argMultimap.getPreamble().isEmpty()) {
            throw new ParseException(String.format(MESSAGE_INVALID_COMMAND_FORMAT, SetShorthandCommand.MESSAGE_USAGE));
        }
        argMultimap.verifyNoDuplicatePrefixesFor(PREFIX_ORIGINAL_COMMAND, PREFIX_SHORTHAND);
        String shorthand = argMultimap.getValue(PREFIX_SHORTHAND).get().trim();
        if (!shorthand.matches(CommandAliasMap.VALIDATION_REGEX)) {
            throw new ParseException(MESSAGE_INVALID_SHORTHAND);
        }
        return new SetShorthandCommand(argMultimap.getValue(PREFIX_ORIGINAL_COMMAND).get().trim(), shorthand);
    }

    /**
     * Returns true if none of the prefixes contains empty {@code Optional} values in the given
     * {@code ArgumentMultimap}.
     */
    private static boolean arePrefixesPresent(ArgumentMultimap argumentMultimap, Prefix... prefixes) {
        return Stream.of(prefixes).allMatch(prefix -> argumentMultimap.getValue(prefix).isPresent());
    }
}
