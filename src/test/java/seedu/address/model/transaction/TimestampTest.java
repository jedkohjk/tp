package seedu.address.model.transaction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static seedu.address.testutil.Assert.assertThrows;

import org.junit.jupiter.api.Test;

public class TimestampTest {

    @Test
    public void constructor_null_throwsNullPointerException() {
        assertThrows(NullPointerException.class, () -> new Timestamp(null));
    }

    @Test
    public void constructor_invalidTimestamp_throwsIllegalArgumentException() {
        String invalidTimestamp = "";
        assertThrows(IllegalArgumentException.class, () -> new Timestamp(invalidTimestamp));
    }

    @Test
    public void isValidTimestamp() {
        // null timestamp
        assertThrows(NullPointerException.class, () -> Timestamp.isValidTimestamp(null));

        // invalid timestamps
        assertFalse(Timestamp.isValidTimestamp("")); // empty string
        assertFalse(Timestamp.isValidTimestamp(" ")); // spaces only
        assertFalse(Timestamp.isValidTimestamp("2023-10-13T12:34")); // incorrect format
        assertFalse(Timestamp.isValidTimestamp("12/13/2020 12:00")); // invalid date
        assertFalse(Timestamp.isValidTimestamp("12/00/2020 12:00")); // invalid date
        assertFalse(Timestamp.isValidTimestamp("00/12/2020")); // invalid date
        assertFalse(Timestamp.isValidTimestamp("12/12/2020 24:00")); // invalid time
        assertFalse(Timestamp.isValidTimestamp("23:60")); // invalid time
        assertFalse(Timestamp.isValidTimestamp("12/12/2020  12:00")); // extra space
        assertFalse(Timestamp.isValidTimestamp("12:00 12/12/2020")); // time before date

        // valid timestamps
        assertTrue(Timestamp.isValidTimestamp("12/12/2020 12:00"));
        assertTrue(Timestamp.isValidTimestamp("12:00"));
        assertTrue(Timestamp.isValidTimestamp("00:00"));
        assertTrue(Timestamp.isValidTimestamp("23:59"));
        assertTrue(Timestamp.isValidTimestamp("12/12/2020"));

    }

    @Test
    public void hashcode() {
        Timestamp timestamp = new Timestamp("13/10/2023 12:34");
        Timestamp otherTimestamp = new Timestamp("13/10/2023 12:34");
        assertEquals(timestamp.hashCode(), otherTimestamp.hashCode());
    }

    @Test
    public void equals() {
        Timestamp timestamp = new Timestamp("13/10/2023 12:34");

        // same values -> returns true
        assertEquals(timestamp, new Timestamp("13/10/2023 12:34"));

        // same object -> returns true
        assertEquals(timestamp, timestamp);

        // null -> returns false
        assertNotEquals(null, timestamp);

        // different types -> returns false
        assertFalse(timestamp.equals(5.0f));

        // different values -> returns false
        assertNotEquals(timestamp, new Timestamp("13/10/2023 12:33"));
    }

    @Test
    public void compareTo() {
        Timestamp timestamp1 = new Timestamp("13/10/2023 12:34");
        Timestamp timestamp2 = new Timestamp("13/10/2023");

        // same value
        assertTrue(timestamp1.compareTo(new Timestamp("13/10/2023 12:34")) == 0);

        // smaller value
        assertTrue(timestamp1.compareTo(timestamp2) > 0);

        // larger value
        assertTrue(timestamp2.compareTo(timestamp1) < 0);
    }
}
