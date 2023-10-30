package seedu.address.logic.parser;

import static seedu.address.logic.Messages.MESSAGE_INVALID_COMMAND_FORMAT;
import static seedu.address.logic.parser.CliSyntax.PREFIX_ORIGINAL_COMMAND;
import static seedu.address.logic.parser.CliSyntax.PREFIX_SHORTHAND;
import static seedu.address.logic.parser.CommandParserTestUtil.assertParseFailure;
import static seedu.address.logic.parser.CommandParserTestUtil.assertParseSuccess;

import org.junit.jupiter.api.Test;

import seedu.address.logic.commands.SetShorthandCommand;

public class SetShorthandCommandParserTest {
    private SetShorthandCommandParser parser = new SetShorthandCommandParser();

    @Test
    public void parse_allFieldsPresent_success() {
        assertParseSuccess(parser, " " + PREFIX_ORIGINAL_COMMAND + SetShorthandCommand.COMMAND_WORD
                + " " + PREFIX_SHORTHAND + "a", new SetShorthandCommand(SetShorthandCommand.COMMAND_WORD, "a"));
    }

    @Test
    public void parse_compulsoryFieldMissing_failure() {
        String expectedMessage = String.format(MESSAGE_INVALID_COMMAND_FORMAT, SetShorthandCommand.MESSAGE_USAGE);
        assertParseFailure(parser, " " + SetShorthandCommand.COMMAND_WORD
                + " " + PREFIX_SHORTHAND + "a", expectedMessage);
        assertParseFailure(parser, " " + PREFIX_ORIGINAL_COMMAND + SetShorthandCommand.COMMAND_WORD
                + " " + "a", expectedMessage);
    }

    @Test
    public void parse_inValidValue_failure() {
        assertParseFailure(parser, " " + PREFIX_ORIGINAL_COMMAND + SetShorthandCommand.COMMAND_WORD
                + " " + PREFIX_SHORTHAND + "123", SetShorthandCommandParser.MESSAGE_INVALID_SHORTHAND);
        assertParseFailure(parser, " " + PREFIX_ORIGINAL_COMMAND + SetShorthandCommand.COMMAND_WORD
                + " " + PREFIX_SHORTHAND, SetShorthandCommandParser.MESSAGE_INVALID_SHORTHAND);
    }
}
