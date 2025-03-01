package com.restaurant.management.service;

import com.restaurant.management.model.Dish;
import com.restaurant.management.model.Inventory;
import com.restaurant.management.model.Recipe;
import com.restaurant.management.repository.RecipeRepository;
import com.sun.jna.platform.win32.OaIdl;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;

@Transactional
@Service
public class RecipeService {
    @Autowired
    private RecipeRepository recipeRepository;

    @Autowired
    private InventoryService inventoryService;

    @Autowired
    private DishService dishService;

    //xoa cong thuc cu va chi them nguyen lieu co so luong > 0
    public void updateRecipesForDish(Dish dish, Map<String, String> params) throws IOException {
        //tao danh sach luu cong thuc moi
        List<Recipe> recipesToUpdate = new ArrayList<>();

        Double costDish = 0.0;

        for(Map.Entry<String, String> entry : params.entrySet()) {
            //lay inventoryId, quantity
            String inventoryIdStr = entry.getKey();
            String quantityRequiredStr = entry.getValue();

            if(inventoryIdStr != null && quantityRequiredStr != null){
                try{
                    Long inventoryId = Long.parseLong(inventoryIdStr);
                    int quantity = Integer.parseInt(quantityRequiredStr);

                    if(quantity>0){
                        Inventory inventory = inventoryService.getById(inventoryId);

                        Recipe recipe = new Recipe();
                        recipe.setDish(dish);
                        recipe.setInventory(inventory);
                        recipe.setQuantityRequired(quantity);
                        recipesToUpdate.add(recipe);

                        // tinh chi phi cua mon an
                        costDish += inventory.getUnitPrice() * quantity;
                    }
                }
                catch(NumberFormatException e){
                    System.err.println("Invalid data: inventoryId=" + inventoryIdStr + ", quantityRequired=" + quantityRequiredStr);
                }
            }
        }

        dish.setCost(costDish);
        dishService.saveDish(dish, null);

        recipeRepository.deleteByDish(dish);
        recipeRepository.saveAll(recipesToUpdate);
    }
}
