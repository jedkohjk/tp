package seedu.address.ui;

import java.util.Map;

import org.apache.commons.numbers.fraction.BigFraction;

import javafx.beans.binding.Bindings;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.SortedList;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import seedu.address.commons.util.FractionUtil;
import seedu.address.model.person.Name;
import seedu.address.model.transaction.Transaction;

/**
 * An UI component that displays information of a {@code Transaction}.
 */
public class TransactionCard extends UiPart<Region> {

    private static final String FXML = "TransactionListCard.fxml";
    private static final int ROW_HEIGHT = 20;

    /**
     * Note: Certain keywords such as "location" and "resources" are reserved keywords in JavaFX.
     * As a consequence, UI elements' variable names cannot be set to such keywords
     * or an exception will be thrown by JavaFX during runtime.
     *
     * @see <a href="https://github.com/se-edu/addressbook-level4/issues/336">The issue on AddressBook level 4</a>
     */

    public final Transaction transaction;

    @FXML
    private HBox transactionCardPane;
    @FXML
    private Label description;
    @FXML
    private Label id;
    @FXML
    private Label date;
    @FXML
    private Label payee;
    @FXML
    private Label amount;
    @FXML
    private Label change;
    @FXML
    private ListView<Name> portionListView;

    /**
     * Creates a {@code TransactionCode} with the given {@code Transaction} and index to display.
     */
    public TransactionCard(Transaction transaction, int displayedIndex) {
        super(FXML);
        this.transaction = transaction;
        Map<Name, BigFraction> subtotals = transaction.getAllPortionAmounts();
        ObservableList<Name> lst = new SortedList<>(FXCollections.observableArrayList(
            subtotals.keySet()), (name1, name2) -> name1.compareTo(name2));
        id.setText(displayedIndex + ". ");
        description.setText(transaction.getDescription().toString());
        date.setText(transaction.getTimestamp().toString());
        NameLabel.setNameLabel(payee, transaction.getPayeeName());
        amount.setText(transaction.getAmount().toString());
        portionListView.setItems(lst);
        if (transaction.getPayeeName().equals(Name.SELF)) {
            change.setText("-");
            portionListView.setCellFactory(listView -> new PortionListViewCell(subtotals, true));
        } else {
            change.setText("-" + FractionUtil.toString(subtotals.get(Name.SELF), 2));
            portionListView.setCellFactory(listView -> new PortionListViewCell(subtotals, false));
        }
        portionListView.prefHeightProperty().bind(Bindings.size(lst).multiply(ROW_HEIGHT));
    }

    /**
     * Custom {@code ListCell} that displays the graphics of a {@code Portion} using a {@code PortionListView}.
     */
    class PortionListViewCell extends ListCell<Name> {
        private Map<Name, BigFraction> map;
        private boolean isCredit;

        PortionListViewCell(Map<Name, BigFraction> map, boolean isCredit) {
            this.map = map;
            this.isCredit = isCredit;
        }

        @Override
        protected void updateItem(Name name, boolean empty) {
            super.updateItem(name, empty);
            if (empty || name == null) {
                setGraphic(null);
                setText(null);
            } else {
                String subtotal = FractionUtil.toString(map.get(name), 2);
                String change = "-";
                if (isCredit && !Name.RESERVED_NAMES.contains(name)) {
                    change = "+" + subtotal;
                }
                setGraphic(new PortionListView(name, subtotal, change, getIndex() + 1).getRoot());
            }
        }
    }
}
