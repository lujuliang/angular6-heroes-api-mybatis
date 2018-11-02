package org.itrunner.heroes.service;

import java.util.List;
import java.util.stream.Collectors;

import org.itrunner.heroes.dao.HeroDao;
import org.itrunner.heroes.dto.HeroCriteria;
import org.itrunner.heroes.dto.HeroDTO;
import org.itrunner.heroes.model.Hero;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class HeroService {
    @Autowired
    private HeroDao heroDao;

    public Hero getHeroById(Long id) {
    	Hero hero = new Hero();
        BeanUtils.copyProperties(heroDao.selectByPrimaryKey(id), hero);
        return hero;
    }

    public List<Hero> getAllHeroes() {
    	HeroCriteria criteria  = new HeroCriteria();
        return heroDao.selectByCriteria(criteria).stream().map(dto->{
        	return convertToBo(dto);
            }).collect(Collectors.toList());
    }

	private Hero convertToBo(HeroDTO dto) {
		Hero hero = new Hero();
		BeanUtils.copyProperties(dto, hero);
		return hero;
	}
	
	private HeroDTO convertToDTO(Hero bo) {
		HeroDTO hero = new HeroDTO();
		BeanUtils.copyProperties(bo, hero);
		return hero;
	}

    public List<Hero> findHeroesByName(String name) {
    	HeroCriteria criteria  = new HeroCriteria();
    	criteria.createCriteria().andNameLike(name);
        return heroDao.selectByCriteria(criteria).stream().map(dto->{
        	return convertToBo(dto);
        }).collect(Collectors.toList());
    }

    public void saveHero(Hero hero) {
    	if(hero.getId() != null) {
    		heroDao.insert(convertToDTO(hero));
    	} else {
    		heroDao.updateByPrimaryKeySelective(convertToDTO(hero));
    	}
       
    }

    public void deleteHero(Long id) {
        heroDao.deleteByPrimaryKey(id);
    }
}
