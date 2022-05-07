from django.test import TestCase
from route.models import Manager,Merchandiser,Comment,Address,User
# Create your tests here.

class ManagerTestClass(TestCase):
    def setUp(self):
        self.manager = Manager(name='Melody',description='I am the Manager at xyz Company',phone_number='+254256272',location='Nairobi')

    def test_instance(self):
        self.assertTrue(isinstance(self.manager,Manager))

    def test_save_manager(self):
        self.manager.save_manager()
        managers = Manager.objects.all()
        self.assertTrue(len(managers) > 0)

class MerchandiserTest(TestCase):
    def create_merchandiser(self,username='Caleb',phone_number='+54378921',email='caleb@gmail.com',location='Narok'):
        return Merchandiser.objects.create(username=username,phone_number=phone_number,email=email,location=location)

    def test_merchan_instance(self):
        merchandisers = self.create_merchandiser()
        self.assertTrue(isinstance(merchandisers,Merchandiser))
        self.assertEqual(merchandisers.__str__(),merchandisers.username)

    # def test_save_merchandiser(self):
    #     self.merchandisers.save_merch()
    #     merchandisers = Merchandiser.objects.all()
    #     self.assertTrue(len(merchandisers) > 0)

class AddressTest(TestCase):
    def create_address(self,city = 'Nakuru',location='Kenya'):
        return Address.objects.create(city=city,location=location)
    
    def test_address_instance(self):
        addresses = self.create_address()
        self.assertTrue(isinstance(addresses,Address))
        self.assertEqual(addresses.__str__(),addresses.city)

    # def test_save_adress(self):
    #     self.addresses.save_address()


class CommentTest(TestCase):
    def setUp(self):
        user=User.objects.create_user(username='Jane',email='melo@gmail.com',password='12hu39')
        self.comment=Comment(date='12/01/2022',content='working from monday to friday',user=user)
       
    def test_comment_instance(self):
        self.assertTrue(isinstance(self.comment,Comment))

    # def test_save_comment(self):
    #     self.comment.save_comment()
    #     comments = Comment.objects.all()
    #     self.assertTrue(len(comments) > 0)
