package com.gdu.nhom1.shopproject.controllers;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import com.gdu.nhom1.shopproject.models.Bill;
import com.gdu.nhom1.shopproject.models.Product;
import com.gdu.nhom1.shopproject.services.BillService;
import com.gdu.nhom1.shopproject.services.ProductService;

@Controller
public class BillController {
    @Autowired
    BillService billService;

    @Autowired
    ProductService productService;

//    @GetMapping("/admin/bills")
//    public String listUsers(Model model) {
//        model.addAttribute("bills", billService.getAllBills());
//        return "bills";
//    }
//
//    @GetMapping("/admin/bills/search")
//    public String searchBill(@RequestParam String keyword, Model model) {
//        List<Bill> results = billService.search(keyword);
//        model.addAttribute("bills", results);
//
//        return "bills";
//    }

    @GetMapping("/bills/history/{id}")
    public String updateCategory(@PathVariable int id, Model model) {
        List<Bill> listBills = billService.getAllBills();
        // tao ra danh sach de chua hoa don khi thanh toan thanh cong.
        List<Bill> bills = new ArrayList<Bill>();
        for (int i = 0; i < listBills.size(); i++) {
            if (listBills.get(i).getUser().getId() == id) {
                bills.add(listBills.get(i));
            }
        }
        // tao ra model de chua thong tin can dua ra trang html.
        model.addAttribute("bills", bills);
        return "history";
    }

    @GetMapping("/bills/viewbill/{id}")
    public String viewBill(Model model, @PathVariable int id, HttpSession session) {
        List<Product> productCurrent = productService.getAllProduct();
        List<String> productName = billService.getBillById(id).get().getProductName();
        //
        List<String> products = new ArrayList<>();
        List<Integer> quantities = new ArrayList<>();
        for (String subString : productName) {
            String[] parts = subString.trim().split(" x ");
            if (parts.length == 2) {
                products.add(parts[0].trim());
                quantities.add(Integer.parseInt(parts[1].trim()));
            }
        }
        
        List<Double> prices = new ArrayList<>();
        for (Product product : productCurrent) {
            for (int i = 0; i < products.size(); i++) {
                if (product.getName().equals(products.get(i))) {
                    prices.add(product.getPrice() * quantities.get(i));
                }
            }
        }
        System.out.println(products);
        System.out.println(quantities);
        System.out.println(prices);

        model.addAttribute("bill", billService.getBillById(id).get());
        model.addAttribute("products", products);
        model.addAttribute("quantities", quantities);
        model.addAttribute("prices", prices);
        return "viewBill";

    }

//    @GetMapping("/admin/bills/viewbill/{id}")
//    public String viewBillAmin(Model model, @PathVariable int id, HttpSession session) {
//        List<Product> productCurrent = productService.getAllProduct();
//        List<String> productName = billService.getBillById(id).get().getProductName();
//
//        List<String> products = new ArrayList<>();
//        List<Integer> quantities = new ArrayList<>();
//        for (String subString : productName) {
//            String[] parts = subString.trim().split(" x ");
//            if (parts.length == 2) {
//                products.add(parts[0].trim());
//                quantities.add(Integer.parseInt(parts[1].trim()));
//            }
//        }
//
//        List<Double> prices = new ArrayList<>();
//        for (Product product : productCurrent) {
//            for (int i = 0; i < products.size(); i++) {
//                if (product.getName().equals(products.get(i))) {
//                    prices.add(product.getPrice() * quantities.get(i));
//                }
//            }
//        }
//        System.out.println(products);
//        System.out.println(quantities);
//        System.out.println(prices);
//
//        model.addAttribute("bill", billService.getBillById(id).get());
//        model.addAttribute("products", products);
//        model.addAttribute("quantities", quantities);
//        model.addAttribute("prices", prices);
//        return "viewBillAdmin";
//
//    }
}
