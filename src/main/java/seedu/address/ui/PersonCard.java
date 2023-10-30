package seedu.address.ui;

import java.util.Comparator;

import org.apache.commons.numbers.fraction.BigFraction;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import seedu.address.commons.util.FractionUtil;
import seedu.address.model.person.Person;

/**
 * An UI component that displays information of a {@code Person}.
 */
public class PersonCard extends UiPart<Region> {

    private static final String FXML = "PersonListCard.fxml";

    /**
     * Note: Certain keywords such as "location" and "resources" are reserved keywords in JavaFX.
     * As a consequence, UI elements' variable names cannot be set to such keywords
     * or an exception will be thrown by JavaFX during runtime.
     *
     * @see <a href="https://github.com/se-edu/addressbook-level4/issues/336">The issue on AddressBook level 4</a>
     */

    public final Person person;

    @FXML
    private HBox personCardPane;
    @FXML
    private Label name;
    @FXML
    private Label id;
    @FXML
    private Label balance;
    @FXML
    private Label phone;
    @FXML
    private Label telegramHandle;
    @FXML
    private Label address;
    @FXML
    private Label email;
    @FXML
    private FlowPane tags;

    /**
     * Creates a {@code PersonCode} with the given {@code Person} and index to display.
     */
    public PersonCard(Person person, BigFraction balanceValue, int displayedIndex) {
        super(FXML);
        this.person = person;
        id.setText(displayedIndex + ". ");
        name.setText(person.getName().fullName);
        String balanceString = FractionUtil.toString(balanceValue, 2);
        if (balanceValue.signum() > 0) {
            balanceString = "+" + balanceString;
        }
        balance.setText("Balance: " + balanceString);
        if (person.getPhone() == null) {
            hideLabel(phone);
        } else {
            phone.setText(person.getPhone().value);
        }
        if (person.getTelegramHandle() == null) {
            hideLabel(telegramHandle);
        } else {
            telegramHandle.setText(person.getTelegramHandle().value);
        }
        if (person.getAddress() == null) {
            hideLabel(address);
        } else {
            address.setText(person.getAddress().value);
        }
        if (person.getEmail() == null) {
            hideLabel(email);
        } else {
            email.setText(person.getEmail().value);
        }
        person.getTags().stream()
                .sorted(Comparator.comparing(tag -> tag.tagName))
                .forEach(tag -> tags.getChildren().add(new Label(tag.tagName)));
    }
    private void hideLabel(Label label) {
        label.setVisible(false);
        label.setMinSize(0, 0);
        label.setPrefSize(0, 0);
        label.setMaxSize(0, 0);
    }
}
