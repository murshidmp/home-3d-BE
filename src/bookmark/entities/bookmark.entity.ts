import { Entity, PrimaryGeneratedColumn, ManyToOne, Column } from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Post } from '../../post/entities/post.entity';

@Entity('bookmarks')
export class Bookmark {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => User, (user) => user.bookmarks, { onDelete: 'CASCADE' })
  user: User;

  @ManyToOne(() => Post, (post) => post.bookmarks, { onDelete: 'CASCADE' })
  post: Post;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;
}
